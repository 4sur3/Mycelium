import pytest

from src.circuit_breaker import CircuitBreaker, CircuitOpenError


def test_stays_closed_under_threshold():
    cb = CircuitBreaker(failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    cb.guard()  # no debe lanzar, solo 2 fallos de 3
    assert cb.is_open is False


def test_opens_at_threshold():
    cb = CircuitBreaker(failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    cb.record_failure()
    assert cb.is_open is True
    with pytest.raises(CircuitOpenError):
        cb.guard()


def test_success_resets_consecutive_count():
    cb = CircuitBreaker(failure_threshold=3)
    cb.record_failure()
    cb.record_failure()
    cb.record_success()  # se recupero, el contador vuelve a cero
    cb.record_failure()
    cb.record_failure()
    cb.guard()  # solo 2 fallos consecutivos desde el ultimo exito, sigue cerrado
    assert cb.is_open is False


def test_reset_reopens_circuit_for_retry():
    cb = CircuitBreaker(failure_threshold=2)
    cb.record_failure()
    cb.record_failure()
    assert cb.is_open is True
    cb.reset()
    assert cb.is_open is False
    cb.guard()  # no debe lanzar tras el reset
