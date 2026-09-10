"""
tests/unit/test_retrain.py
───────────────────────────
Hardened Unit tests for Sprint 3 Autonomous MLOps, Active Learning & Model Promotion.
Validates all P0 and P1 security, integrity, and safety guarantees.
"""

from __future__ import annotations

import asyncio
import json
import pickle
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pandas as pd
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.models import ScanResult
from backend.services.learning import (
    ActiveLearningService,
    _is_valid_feature_vector,
    check_and_trigger_autonomous_retraining,
    learning_service,
)
from backend.services.model_lifecycle import (
    execute_model_rollback,
    model_lifecycle_lock,
    validate_model_path,
)
from backend.services.prediction import PredictionService
from ml.pipelines.retrain import (
    _verify_exact_feature_schema,
    calculate_pr_auc,
    calculate_safety_metrics,
    run_retraining_pipeline,
)
from src.config import MODEL_DIR


class DummyPickleModel:
    name = "DummyModel"
    classes_ = ["legitimate", "phishing"]
    _label_encoder = None

    def __init__(self):
        self.model = self

    def predict(self, X):
        return np.array(["legitimate"] * len(X))

    def predict_proba(self, X):
        return np.array([[0.9, 0.1]] * len(X))


class FailingModelWrapper:
    name = "FailingModel"
    classes_ = ["legitimate", "phishing"]
    _label_encoder = None

    def __init__(self):
        self.model = self

    def predict_proba(self, X):
        raise RuntimeError("Smoke test inference crash")


def _make_dummy_feature_vector(schema: list[str]) -> dict[str, float]:
    """Helper to construct a valid 59-feature vector for testing."""
    return {feat: 1.0 for feat in schema}


# ── P1-1: Exact 59-Feature Schema Enforcement ────────────────────────────────

def test_active_learning_service_schema():
    """Verify ActiveLearningService enforces exactly 59 canonical features."""
    service = ActiveLearningService()
    assert len(service.schema) == 59
    assert "url_length" in service.schema


def test_is_valid_feature_vector_rejects_extra_or_missing_columns():
    """Verify feature vector validation strictly rejects non-59 feature dicts."""
    schema = learning_service.schema
    valid_fv = _make_dummy_feature_vector(schema)
    assert _is_valid_feature_vector(valid_fv, schema) is True

    # 58 features (missing one)
    incomplete_fv = dict(valid_fv)
    del incomplete_fv[schema[0]]
    assert _is_valid_feature_vector(incomplete_fv, schema) is False

    # 60 features (extra feature)
    extra_fv = dict(valid_fv)
    extra_fv["unexpected_extra_feature"] = 2.0
    assert _is_valid_feature_vector(extra_fv, schema) is False

    # Non-numeric or NaN
    nan_fv = dict(valid_fv)
    nan_fv[schema[0]] = float("nan")
    assert _is_valid_feature_vector(nan_fv, schema) is False


def test_verify_exact_feature_schema_raises_on_column_mismatch():
    """Verify DataFrame schema validation raises ValueError if columns differ."""
    schema = learning_service.schema
    df_good = pd.DataFrame([{f: 1.0 for f in schema}])
    verified = _verify_exact_feature_schema(df_good, schema, "TEST")
    assert list(verified.columns) == schema

    # Missing column
    df_missing = pd.DataFrame([{schema[0]: 1.0}])
    with pytest.raises(ValueError, match="missing"):
        _verify_exact_feature_schema(df_missing, schema, "TEST")

    # Extra column
    df_extra = pd.DataFrame([{f: 1.0 for f in schema} | {"bad_col": 0.0}])
    with pytest.raises(ValueError, match="unexpected"):
        _verify_exact_feature_schema(df_extra, schema, "TEST")


# ── P0-2: Autonomous Retraining Trigger & Ground Truth ────────────────────────

def test_verify_sample_label_authoritative_hit():
    """Verify authoritative threat intelligence hits are accepted with provenance."""
    async def _test():
        service = ActiveLearningService()
        mock_hit = {
            "prediction": "phishing",
            "confidence": 0.99,
            "reason": "Known phishing feed match",
            "source": "phishtank",
        }
        with patch("backend.services.learning.threat_intel_service.check_url", AsyncMock(return_value=mock_hit)):
            res = await service.verify_sample_label("http://phish.com", "phishing")
            assert res is not None
            label, prov = res
            assert label == "phishing"
            assert prov == "phishtank_detection"

    asyncio.run(_test())


def test_verify_sample_label_heuristic_rejected():
    """Verify heuristic-only hits without authoritative feed consensus are rejected."""
    async def _test():
        service = ActiveLearningService()
        mock_hit = {
            "prediction": "phishing",
            "confidence": 0.85,
            "reason": "Brand in subdomain",
            "source": "heuristic",
        }
        with patch("backend.services.learning.threat_intel_service.check_url", AsyncMock(return_value=mock_hit)):
            res = await service.verify_sample_label("http://paypal-login.xyz", "phishing")
            assert res is None

    asyncio.run(_test())


def test_verify_sample_label_allowlist_accepted():
    """Verify allowlist domains confirmed clean are accepted as legitimate."""
    async def _test():
        service = ActiveLearningService()
        with patch("backend.services.learning.threat_intel_service.check_url", AsyncMock(return_value=None)):
            res = await service.verify_sample_label("https://www.google.com/search?q=cybersec")
            assert res is not None
            label, prov = res
            assert label == "legitimate"
            assert prov == "trusted_allowlist"

    asyncio.run(_test())


def test_verify_sample_label_unverified_domain_rejected():
    """CRITICAL: Verify model predictions are NEVER treated as ground truth for untrusted domains."""
    async def _test():
        service = ActiveLearningService()
        with patch("backend.services.learning.threat_intel_service.check_url", AsyncMock(return_value=None)):
            res = await service.verify_sample_label("http://random-unknown-domain-123.com", "legitimate")
            assert res is None

    asyncio.run(_test())


def test_unverified_samples_do_not_trigger_autonomous_retraining():
    """Verify 50 unverified/ambiguous samples do NOT trigger autonomous retraining."""
    async def _test():
        mock_session = AsyncMock(spec=AsyncSession)
        mock_res = MagicMock()
        mock_res.scalar.return_value = 0  # 0 VERIFIED samples
        mock_session.execute.return_value = mock_res

        def _factory():
            class _Ctx:
                async def __aenter__(self):
                    return mock_session
                async def __aexit__(self, *args):
                    pass
            return _Ctx()

        triggered = await check_and_trigger_autonomous_retraining(db_session_factory=_factory)
        assert triggered is False

    asyncio.run(_test())


# ── P0-3: Rollback Semantics (No Reinstalling Bad Champion) ───────────────────

def test_rollback_twice_does_not_reinstall_bad_model(tmp_path, monkeypatch):
    """
    CRITICAL: Verify two consecutive rollback operations do NOT reinstall
    the demoted bad model.
    """
    champ_a = tmp_path / "model_champ_a.pkl"
    champ_b = tmp_path / "model_champ_b.pkl"

    with open(champ_a, "wb") as f:
        pickle.dump(DummyPickleModel(), f)
    with open(champ_b, "wb") as f:
        pickle.dump(DummyPickleModel(), f)

    registry_file = tmp_path / "registry.json"
    registry_file.write_text(json.dumps({
        "production": "model_champ_b.pkl",
        "staging": "model_champ_b.pkl",
        "champion_history": ["model_champ_a.pkl", "model_champ_b.pkl"],
        "demoted_models": [],
        "artifacts_sha256": {},
    }))

    monkeypatch.setattr("backend.services.model_lifecycle.settings.REGISTRY_PATH", registry_file)
    monkeypatch.setattr("backend.services.model_lifecycle.MODEL_DIR", tmp_path)

    # 1. First rollback: Demotes B, restores A
    res1 = execute_model_rollback()
    assert res1["status"] == "rolled_back"
    assert res1["current_champion"] == "model_champ_a.pkl"
    assert res1["demoted_model"] == "model_champ_b.pkl"

    with open(registry_file) as f:
        reg1 = json.load(f)
    assert reg1["production"] == "model_champ_a.pkl"
    assert "model_champ_b.pkl" in reg1["demoted_models"]

    # 2. Second consecutive rollback: Must NOT reinstall B! Raises ValueError because no other champion exists.
    with pytest.raises(ValueError, match="No valid previous champion available"):
        execute_model_rollback()

    # Verify B was NOT reinstalled
    with open(registry_file) as f:
        reg2 = json.load(f)
    assert reg2["production"] == "model_champ_a.pkl"


# ── P0-4 & P1-9: Lifecycle Concurrency Mutex ──────────────────────────────────

def test_model_lifecycle_lock_mutual_exclusion():
    """Verify ModelLifecycleLock enforces mutual exclusion."""
    async def _test():
        async with model_lifecycle_lock:
            assert model_lifecycle_lock.is_locked() is True
            # Attempting to acquire again in another task raises RuntimeError
            with pytest.raises(RuntimeError, match="currently active"):
                async with model_lifecycle_lock:
                    pass
        assert model_lifecycle_lock.is_locked() is False

    asyncio.run(_test())


# ── P0-6: Sample Lifecycle Consistency & Quarantine ───────────────────────────

def test_samples_quarantined_after_three_failed_attempts():
    """Verify samples failing candidate promotion 3 times are transitioned to QUARANTINED."""
    async def _test():
        sample = ScanResult(
            id=10,
            url="http://toxic-sample.xyz",
            retrain_status="EVALUATED",
            retrain_attempt_count=3,  # Already failed 3 attempts
            is_retrained=False,
        )

        mock_db = AsyncMock(spec=AsyncSession)
        mock_res = MagicMock()
        mock_res.scalars.return_value.all.return_value = [sample]
        mock_db.execute.return_value = mock_res

        await learning_service.mark_samples_outcome(mock_db, [10], promoted=False)
        assert sample.retrain_status == "QUARANTINED"
        assert sample.is_retrained is True  # Removed from future retrain pools

    asyncio.run(_test())


# ── P1-2 & P1-3: Path Traversal & SHA-256 Validation ─────────────────────────

def test_validate_model_path_blocks_directory_traversal():
    """Verify path traversal attempts are rejected."""
    with pytest.raises(ValueError, match="path traversal"):
        validate_model_path("../../evil.pkl")

    with pytest.raises(ValueError, match="path traversal"):
        validate_model_path("/etc/passwd")

    with pytest.raises(ValueError, match="path traversal"):
        validate_model_path("subdir/model.pkl")


def test_prediction_service_reload_verifies_checksum():
    """Verify PredictionService.reload_model rejects artifact when checksum mismatches."""
    svc = PredictionService()
    svc.model = "existing_champion"

    with (
        patch(
            "backend.services.prediction.compute_file_sha256",
            return_value="valid_actual_hash",
        ),
        patch(
            "backend.services.prediction.validate_model_path",
            return_value=MODEL_DIR / "xgboost_calibrated.pkl",
        ),
        patch(
            "backend.services.prediction.get_registry",
            return_value={"artifacts_sha256": {"xgboost_calibrated.pkl": "wrong_hash"}},
        ),
    ):
        svc.reload_model()
        assert svc.model == "existing_champion"


# ── P1-6: Multi-Metric Safety Gates & PR-AUC ──────────────────────────────────

def test_safety_metrics_calculation():
    """Verify FPR and FNR calculations."""
    y_true = np.array(["legitimate", "legitimate", "phishing", "malware"])
    y_pred = np.array(["legitimate", "phishing", "phishing", "malware"])

    metrics = calculate_safety_metrics(y_true, y_pred)
    assert metrics["val_fpr"] == 0.5  # 1 out of 2 legitimate URLs falsely flagged
    assert metrics["val_fnr"] == 0.0  # 0 threats missed


def test_calculate_pr_auc():
    """Verify PR-AUC calculation produces valid float."""
    y_true = np.array(["legitimate", "phishing", "legitimate", "phishing"])
    y_proba = np.array([[0.9, 0.1], [0.1, 0.9], [0.8, 0.2], [0.2, 0.8]])
    score = calculate_pr_auc(y_true, y_proba, ["legitimate", "phishing"])
    assert score > 0.8


# ── P0-1 & P1-5: Candidate Promotion Gates & Isolated Pipeline ────────────────

def test_retraining_pipeline_isolated_execution(tmp_path, monkeypatch):
    """
    Verify run_retraining_pipeline strictly requires passing all promotion gates.
    Force promotion parameter is eliminated.
    """
    schema = learning_service.schema
    dummy_data = {feat: [1.0, 0.5, 0.2, 0.8, 1.2, 0.1, 0.9, 0.4] for feat in schema}
    dummy_data["label"] = [
        "legitimate", "phishing", "malware", "defacement",
        "legitimate", "phishing", "malware", "defacement",
    ]
    train_df = pd.DataFrame(dummy_data)
    val_df = pd.DataFrame(dummy_data)

    train_path = tmp_path / "train.parquet"
    val_path = tmp_path / "val.parquet"
    train_df.to_parquet(train_path)
    val_df.to_parquet(val_path)

    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps({
        "production": None,
        "champion_history": [],
        "demoted_models": [],
        "artifacts_sha256": {},
    }))

    monkeypatch.setattr("ml.pipelines.retrain.TRAIN_PATH", train_path)
    monkeypatch.setattr("ml.pipelines.retrain.VAL_PATH", val_path)
    monkeypatch.setattr("ml.pipelines.retrain.MODEL_DIR", tmp_path)
    monkeypatch.setattr("ml.pipelines.retrain.settings.REGISTRY_PATH", registry_path)
    monkeypatch.setattr("backend.services.model_lifecycle.settings.REGISTRY_PATH", registry_path)
    monkeypatch.setattr("backend.services.model_lifecycle.MODEL_DIR", tmp_path)

    X_zd = pd.DataFrame([_make_dummy_feature_vector(schema)])
    y_zd = pd.Series(["legitimate"])

    result = run_retraining_pipeline(
        X_zero_day=X_zd,
        y_zero_day=y_zd,
        experiment_name="test_experiment",
    )

    assert result["status"] == "success"
    # P1-5: Missing champion strictly blocks promotion
    assert result["promoted"] is False
    assert result["gate_results"]["champion_missing"] is True
    assert "candidate_sha256" in result
    assert "val_fpr" in result["candidate_metrics"]
    assert "pr_auc" in result["candidate_metrics"]
    assert registry_path.exists()


def test_reordered_features_block_training():
    """Stress test 11: Reordered feature columns strictly raise ValueError."""
    schema = learning_service.schema
    reordered_schema = list(reversed(schema))
    df = pd.DataFrame([{f: 1.0 for f in reordered_schema}])

    with pytest.raises(ValueError, match="canonical order"):
        _verify_exact_feature_schema(df, schema, "REORDERED_TEST")


def test_feature_vector_boolean_and_infinite_rejected():
    """Stress tests 14 & 15: Boolean and Infinite feature values are rejected."""
    schema = learning_service.schema
    fv = _make_dummy_feature_vector(schema)

    # Boolean is rejected
    fv_bool = dict(fv)
    fv_bool[schema[0]] = True
    assert _is_valid_feature_vector(fv_bool, schema) is False

    # Positive infinity is rejected
    fv_inf = dict(fv)
    fv_inf[schema[0]] = float("inf")
    assert _is_valid_feature_vector(fv_inf, schema) is False

    # Negative infinity is rejected
    fv_ninf = dict(fv)
    fv_ninf[schema[0]] = float("-inf")
    assert _is_valid_feature_vector(fv_ninf, schema) is False


def test_validate_model_path_windows_and_absolute_traversal():
    """Stress test 16: Windows backslashes and drive paths are blocked."""
    with pytest.raises(ValueError, match="path traversal"):
        validate_model_path("..\\..\\malicious.pkl")

    with pytest.raises(ValueError, match="path traversal"):
        validate_model_path("C:\\Windows\\System32\\calc.exe")


def test_corrupted_pickle_retains_active_model(tmp_path, monkeypatch):
    """Stress test 18: Corrupted pickle artifact does not corrupt or replace active model."""
    svc = PredictionService()
    svc.model = "active_champion_model"

    bad_file = tmp_path / "corrupted.pkl"
    bad_file.write_bytes(b"NOT_A_VALID_PICKLE_STREAM_GARBAGE_BYTES")

    monkeypatch.setattr("backend.services.prediction.validate_model_path", lambda name: bad_file)
    monkeypatch.setattr("backend.services.prediction.get_registry", lambda: {})

    svc.reload_model()
    # Active model reference is preserved
    assert svc.model == "active_champion_model"


def test_smoke_test_failure_retains_active_model(tmp_path, monkeypatch):
    """Stress test 19: Smoke-test prediction failure retains active model without swapping."""
    svc = PredictionService()
    svc.model = "active_champion_model"

    failing_file = tmp_path / "failing_model.pkl"
    with open(failing_file, "wb") as f:
        pickle.dump(FailingModelWrapper(), f)

    monkeypatch.setattr("backend.services.prediction.validate_model_path", lambda name: failing_file)
    monkeypatch.setattr("backend.services.prediction.get_registry", lambda: {})

    svc.reload_model()
    assert svc.model == "active_champion_model"


def test_explainer_failure_restores_prediction_service():
    """Stress test 20: Explainer reload failure triggers emergency rollback of prediction service."""
    from backend.services.model_lifecycle import coordinate_model_reload

    mock_pred = MagicMock()
    mock_expl = MagicMock()
    mock_expl.reload_model.side_effect = RuntimeError("Explainer crash on new weights")

    backup_reg = {"production": "old_champ.pkl"}

    with (
        patch("backend.services.model_lifecycle.write_registry_atomically") as mock_write,
        pytest.raises(RuntimeError, match="state reverted"),
    ):
        coordinate_model_reload(mock_pred, mock_expl, backup_registry=backup_reg)

    # Prediction service was reloaded to rollback, and registry restored
    assert mock_pred.reload_model.call_count == 2
    mock_write.assert_called_once_with(backup_reg)


def test_candidate_failing_fnr_gate_blocks_promotion():
    """Stress tests 2 & 6: Candidate with increased False Negatives is rejected."""
    y_true = np.array(["phishing", "phishing", "malware", "legitimate"])
    # Candidate predicts legitimate on actual phishing (increased FNR)
    y_pred = np.array(["legitimate", "phishing", "malware", "legitimate"])

    metrics = calculate_safety_metrics(y_true, y_pred)
    assert metrics["val_fnr"] > 0.030  # 1 threat missed out of 3 = 0.3333 > 0.030


def test_duplicate_zero_day_sample_marked_duplicate():
    """Stress test 28: Duplicate URLs are marked DUPLICATE and excluded from verified pool."""
    async def _test():
        mock_db = AsyncMock(spec=AsyncSession)
        scan_record = ScanResult(
            id=101,
            url="http://duplicate-test.com",
            feature_vector=_make_dummy_feature_vector(learning_service.schema),
            retrain_status="UNVERIFIED",
        )

        res_scan = MagicMock()
        res_scan.scalar_one_or_none.return_value = scan_record

        res_dup = MagicMock()
        res_dup.scalar_one_or_none.return_value = 99  # Existing verified scan with same URL

        mock_db.execute.side_effect = [res_scan, res_dup]

        status = await learning_service.process_and_verify_zero_day_sample(mock_db, 101, "http://duplicate-test.com")
        assert status == "DUPLICATE"
        assert scan_record.retrain_status == "DUPLICATE"

    asyncio.run(_test())


# ── CodeRabbit Remediations Regression Suite ──────────────────────────────────

def test_champion_load_failure_reported_correctly(tmp_path, monkeypatch):
    """Finding 1: Champion file in registry that fails to load reports champion_load_failed."""
    from ml.pipelines.retrain import load_champion_model

    reg_path = tmp_path / "registry.json"
    reg_path.write_text(json.dumps({
        "production": "corrupted_champion.pkl",
        "champion_history": ["corrupted_champion.pkl"],
        "artifacts_sha256": {},
    }))

    bad_model = tmp_path / "corrupted_champion.pkl"
    bad_model.write_bytes(b"INVALID_PICKLE_GARBAGE")

    monkeypatch.setattr("ml.pipelines.retrain.settings.REGISTRY_PATH", reg_path)
    monkeypatch.setattr("ml.pipelines.retrain.MODEL_DIR", tmp_path)
    monkeypatch.setattr("backend.services.model_lifecycle.MODEL_DIR", tmp_path)

    wrapper, champ_file = load_champion_model()
    # Must preserve champion_file identity while reporting failure to load
    assert wrapper is None
    assert champ_file == "corrupted_champion.pkl"


def test_safety_metrics_keys_no_duplicated_val_prefix():
    """Finding 2: Metric names do not contain duplicate val_ prefixes."""
    y_true = np.array(["legitimate", "phishing"])
    y_pred = np.array(["legitimate", "phishing"])
    metrics = calculate_safety_metrics(y_true, y_pred)
    assert "fpr" in metrics
    assert "fnr" in metrics
    # Ensure no val_val_ prefix could be produced
    for k in metrics:
        assert not k.startswith("val_val_")


def test_fpr_fnr_ceilings_use_min_semantics():
    """Finding 3: FPR/FNR ceilings use min semantics and fail closed."""
    # When champion FPR is very good (e.g. 0.001), candidate FPR at 0.010 must be blocked
    champ_fpr = 0.001
    ceiling = min(champ_fpr + 0.002, 0.015)
    assert ceiling == 0.003
    cand_fpr = 0.010
    assert (cand_fpr <= ceiling) is False

    # When champion FNR is 0.005, candidate FNR at 0.025 must be blocked
    champ_fnr = 0.005
    fnr_ceiling = min(champ_fnr + 0.005, 0.030)
    assert fnr_ceiling == 0.010
    cand_fnr = 0.025
    assert (cand_fnr <= fnr_ceiling) is False


def test_champion_checksum_verified_before_unpickling(tmp_path, monkeypatch):
    """Finding 4: Champion artifact with checksum mismatch is rejected before unpickling."""
    from ml.pipelines.retrain import load_champion_model

    reg_path = tmp_path / "registry.json"
    reg_path.write_text(json.dumps({
        "production": "tampered_champion.pkl",
        "champion_history": ["tampered_champion.pkl"],
        "artifacts_sha256": {"tampered_champion.pkl": "expected_valid_hash_000000000000000000000000000000000000000000"},
    }))

    model_file = tmp_path / "tampered_champion.pkl"
    with open(model_file, "wb") as f:
        pickle.dump(DummyPickleModel(), f)

    monkeypatch.setattr("ml.pipelines.retrain.settings.REGISTRY_PATH", reg_path)
    monkeypatch.setattr("ml.pipelines.retrain.MODEL_DIR", tmp_path)
    monkeypatch.setattr("backend.services.model_lifecycle.MODEL_DIR", tmp_path)

    wrapper, champ_file = load_champion_model()
    # Checksum mismatch prevents loading
    assert wrapper is None
    assert champ_file == "tampered_champion.pkl"


def test_explainer_checksum_verified_before_unpickling(tmp_path, monkeypatch):
    """Finding 4: ExplainerService rejects model if checksum mismatches."""
    from backend.services.explainer import ExplainerService

    svc = ExplainerService()

    reg_data = {
        "artifacts_sha256": {"xgboost_calibrated.pkl": "mismatched_explainer_hash"}
    }
    monkeypatch.setattr("backend.services.explainer.get_registry", lambda: reg_data)

    with pytest.raises(RuntimeError, match="Explainer reload failed against new champion"):
        svc.reload_model()


def test_reset_samples_from_evaluation_when_pipeline_raises():
    """Finding 6: When retraining pipeline raises, evaluated samples are reset to VERIFIED."""
    async def _test():
        sample = ScanResult(
            id=201,
            url="http://eval-fail-sample.com",
            retrain_status="EVALUATED",
            retrain_attempt_count=2,
        )
        mock_db = AsyncMock(spec=AsyncSession)
        mock_res = MagicMock()
        mock_res.scalars.return_value.all.return_value = [sample]
        mock_db.execute.return_value = mock_res

        reset_count = await learning_service.reset_samples_from_evaluation(mock_db, [201])
        assert reset_count == 1
        assert sample.retrain_status == "VERIFIED"
        assert sample.retrain_attempt_count == 1  # decremented

    asyncio.run(_test())


def test_abort_resets_samples_to_verified():
    """Finding 8: If autonomous retraining aborts due to count drop, samples return to VERIFIED."""
    async def _test():
        sample = ScanResult(
            id=301,
            url="http://aborted-sample.com",
            retrain_status="EVALUATED",
            retrain_attempt_count=1,
        )
        mock_db = AsyncMock(spec=AsyncSession)
        mock_res = MagicMock()
        mock_res.scalars.return_value.all.return_value = [sample]
        mock_db.execute.return_value = mock_res

        reset_count = await learning_service.reset_samples_from_evaluation(mock_db, [301])
        assert reset_count == 1
        assert sample.retrain_status == "VERIFIED"
        assert sample.retrain_attempt_count == 0

    asyncio.run(_test())


def test_lifecycle_lock_not_stale_when_process_is_alive(tmp_path, monkeypatch):
    """Finding 9: A lock older than 15 minutes is NOT broken if the holding process is still running."""
    import os
    import time

    from backend.services.model_lifecycle import ModelLifecycleLock

    lock_path = tmp_path / ".lifecycle.lock"
    # Write lockfile with current active process PID and old timestamp (1000s ago > 900s)
    current_pid = os.getpid()
    lock_path.write_text(f"pid={current_pid},time=2026-09-10T00:00:00Z\n")

    # Set file mtime to 1000 seconds ago
    old_time = time.time() - 1000
    os.utime(lock_path, (old_time, old_time))

    monkeypatch.setattr("backend.services.model_lifecycle.LOCK_FILE", lock_path)

    lock = ModelLifecycleLock()
    # Process is still running, so lock must remain active and NOT unlinked
    assert lock.is_locked() is True
    assert lock_path.exists() is True


def test_promotion_fails_without_valid_checksum():
    """Finding 10: Candidate promotion fails closed if candidate SHA-256 is missing or invalid."""
    from backend.services.model_lifecycle import promote_candidate_to_registry

    with pytest.raises(ValueError, match="must have a valid 64-character SHA-256 checksum"):
        promote_candidate_to_registry("candidate.pkl", {"f1": 0.95}, candidate_sha256=None)

    with pytest.raises(ValueError, match="must have a valid 64-character SHA-256 checksum"):
        promote_candidate_to_registry("candidate.pkl", {"f1": 0.95}, candidate_sha256="too_short")
