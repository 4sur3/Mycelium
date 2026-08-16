from src.summary_cache import SummaryCache, content_cache_key


def test_content_cache_key_is_deterministic():
    assert content_cache_key("mismo texto") == content_cache_key("mismo texto")


def test_content_cache_key_differs_for_different_text():
    assert content_cache_key("texto A") != content_cache_key("texto B")


def test_cache_miss_then_hit(tmp_path):
    cache = SummaryCache(tmp_path / "cache.json")
    key = content_cache_key("contenido de ejemplo")

    assert cache.get(key) is None  # miss
    cache.set(key, "Un resumen cualquiera.")
    assert cache.get(key) == "Un resumen cualquiera."  # hit

    stats = cache.stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["cached_entries"] == 1


def test_cache_persists_across_instances(tmp_path):
    path = tmp_path / "cache.json"
    key = content_cache_key("contenido persistente")

    cache1 = SummaryCache(path)
    cache1.set(key, "Resumen guardado.")
    cache1.save()

    cache2 = SummaryCache(path)  # nueva instancia, mismo fichero
    assert cache2.get(key) == "Resumen guardado."


def test_cache_survives_corrupted_file(tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("esto no es json valido {{{", encoding="utf-8")
    cache = SummaryCache(path)  # no debe lanzar excepcion
    assert cache.size == 0


def test_multiple_domains_sharing_content_only_pay_once():
    """
    Simula el escenario real que motiva esta cache: N dominios con el
    MISMO contenido exacto (plantilla compartida) solo deberian generar
    UNA llamada real al LLM; el resto se sirven de la cache.
    """
    shared_text = "Bienvenido a nuestro exchange automatico de criptomonedas."
    key = content_cache_key(shared_text)

    llm_calls = 0

    def summarize_with_cache(cache, text):
        nonlocal llm_calls
        cache_key = content_cache_key(text)
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        llm_calls += 1
        summary = f"[resumen simulado de: {text[:20]}...]"
        cache.set(cache_key, summary)
        return summary

    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        cache = SummaryCache(Path(tmp) / "cache.json")
        domains_sharing_template = 12
        for _ in range(domains_sharing_template):
            summarize_with_cache(cache, shared_text)

        assert llm_calls == 1  # solo se llamo al LLM una vez, no 12
        assert cache.stats()["hits"] == domains_sharing_template - 1
