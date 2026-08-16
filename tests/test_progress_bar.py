from src.progress_bar import format_duration, render_progress_bar


def test_format_duration_seconds_only():
    assert format_duration(45) == "45s"


def test_format_duration_minutes_and_seconds():
    assert format_duration(252) == "4m12s"


def test_format_duration_hours_and_minutes():
    assert format_duration(5000) == "1h23m"


def test_format_duration_zero():
    assert format_duration(0) == "0s"


def test_format_duration_negative_clamped_to_zero():
    assert format_duration(-5) == "0s"


def test_render_progress_bar_at_start():
    line = render_progress_bar(current=0, total=100, start_time=__import__("time").monotonic())
    assert "0.0%" in line
    assert "(0/100)" in line


def test_render_progress_bar_at_completion():
    import time
    start = time.monotonic() - 10  # simula que ya pasaron 10s
    line = render_progress_bar(current=100, total=100, start_time=start)
    assert "100.0%" in line
    assert "(100/100)" in line
    assert "restante_est=0s" in line


def test_render_progress_bar_includes_suffix():
    import time
    line = render_progress_bar(current=1, total=10, start_time=time.monotonic(), suffix="resumidos=1")
    assert "resumidos=1" in line


def test_render_progress_bar_empty_total_returns_empty_string():
    import time
    assert render_progress_bar(current=0, total=0, start_time=time.monotonic()) == ""


def test_render_progress_bar_eta_decreases_as_progress_increases():
    import time
    start = time.monotonic() - 10  # 10s transcurridos, ritmo conocido
    line_25pct = render_progress_bar(current=25, total=100, start_time=start)
    line_75pct = render_progress_bar(current=75, total=100, start_time=start)
    # ritmo: 25/10s=2.5/s -> restantes 75/2.5=30s; 75/10s=7.5/s -> restantes 25/7.5=3s
    assert "restante_est=30s" in line_25pct
    assert "restante_est=3s" in line_75pct
