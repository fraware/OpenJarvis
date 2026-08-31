from pathlib import Path

path = Path("tests/engine/test_discovery.py")
text = path.read_text(encoding="utf-8")

old_init = '''    def __init__(
        self,
        *,
        healthy: bool = True,
        models: list | None = None,
        **kwargs,  # noqa: ANN003
    ) -> None:
        self._healthy = healthy
        self._models = models or []
'''
new_init = '''    def __init__(
        self,
        *,
        healthy: bool = True,
        models: list | None = None,
        host: str | None = None,
        **kwargs,  # noqa: ANN003
    ) -> None:
        self._healthy = healthy
        self._models = models or []
        if host is not None:
            self._host = host
'''
assert old_init in text
text = text.replace(old_init, new_init, 1)

old_same = '''    def test_default_fallback_prefers_same_engine_class(self) -> None:
        _reg("bad-local", "bad-local")
        _reg("a-cloud", "a-cloud")
        _reg("z-local", "z-local")

        class _Cloud(_FakeEngine):
            is_cloud = True

        cfg = JarvisConfig()
        cfg.engine.default = "bad-local"

        def _make(k, c):  # noqa: ANN001
            if k == "bad-local":
                return _FakeEngine(healthy=False)
            if k == "a-cloud":
                return _Cloud(healthy=True)
            return _FakeEngine(healthy=(k == "z-local"))

        with mock.patch(
            "openjarvis.engine._discovery._make_engine",
            side_effect=_make,
        ):
            result = get_engine(cfg)

        assert result is not None
        assert result[0] == "z-local"
'''
new_same = '''    def test_default_fallback_prefers_same_host_egress_class(self) -> None:
        _reg("bad-local", "bad-local")
        _reg("a-cloud", "a-cloud")
        _reg("z-local", "z-local")

        class _Cloud(_FakeEngine):
            is_cloud = True

        cfg = JarvisConfig()
        cfg.engine.default = "bad-local"

        def _make(k, c):  # noqa: ANN001
            if k == "bad-local":
                return _FakeEngine(
                    healthy=False,
                    host="http://localhost:9100",
                )
            if k == "a-cloud":
                return _Cloud(healthy=True)
            return _FakeEngine(
                healthy=(k == "z-local"),
                host="http://127.0.0.1:9200",
            )

        with mock.patch(
            "openjarvis.engine._discovery._make_engine",
            side_effect=_make,
        ):
            result = get_engine(cfg)

        assert result is not None
        assert result[0] == "z-local"
'''
assert old_same in text
text = text.replace(old_same, new_same, 1)

old_cross = '''    def test_cross_boundary_default_fallback_is_named(self, caplog) -> None:
        _reg("bad-local", "bad-local")
        _reg("cloud-only", "cloud-only")

        class _Cloud(_FakeEngine):
            is_cloud = True

        cfg = JarvisConfig()
        cfg.engine.default = "bad-local"

        def _make(k, c):  # noqa: ANN001
            if k == "bad-local":
                return _FakeEngine(healthy=False)
            return _Cloud(healthy=(k == "cloud-only"))

        with mock.patch(
            "openjarvis.engine._discovery._make_engine",
            side_effect=_make,
        ):
            result = get_engine(cfg)

        assert result is not None
        assert result[0] == "cloud-only"
        assert "across the local/cloud boundary" in caplog.text
'''
new_cross = '''    def test_cross_boundary_default_fallback_is_named(self, caplog) -> None:
        _reg("bad-local", "bad-local")
        _reg("cloud-only", "cloud-only")

        class _Cloud(_FakeEngine):
            is_cloud = True

        cfg = JarvisConfig()
        cfg.engine.default = "bad-local"

        def _make(k, c):  # noqa: ANN001
            if k == "bad-local":
                return _FakeEngine(
                    healthy=False,
                    host="http://localhost:9100",
                )
            return _Cloud(healthy=(k == "cloud-only"))

        with mock.patch(
            "openjarvis.engine._discovery._make_engine",
            side_effect=_make,
        ):
            result = get_engine(cfg)

        assert result is not None
        assert result[0] == "cloud-only"
        assert (
            "across the local-host trust boundary "
            "(local-host -> vendor-cloud)"
        ) in caplog.text

    def test_nim_default_prefers_external_candidate_over_local_candidate(self) -> None:
        _reg("nim", "nim")
        _reg("a-local", "a-local")
        _reg("z-remote", "z-remote")

        cfg = JarvisConfig()
        cfg.engine.default = "nim"

        def _make(k, c):  # noqa: ANN001
            if k == "nim":
                return _FakeEngine(
                    healthy=False,
                    host="https://integrate.api.nvidia.com",
                )
            if k == "a-local":
                return _FakeEngine(
                    healthy=True,
                    host="http://localhost:9300",
                )
            return _FakeEngine(
                healthy=(k == "z-remote"),
                host="https://cluster.example.test",
            )

        with mock.patch(
            "openjarvis.engine._discovery._make_engine",
            side_effect=_make,
        ):
            result = get_engine(cfg)

        assert result is not None
        assert result[0] == "z-remote"
'''
assert old_cross in text
text = text.replace(old_cross, new_cross, 1)

path.write_text(text, encoding="utf-8")
