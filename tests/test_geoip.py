from apps.events import geoip


def _reset_reader():
    geoip._reader = None
    geoip._reader_loaded = False


def test_lookup_returns_empty_when_db_missing(settings, tmp_path):
    settings.GEOIP_PATH = str(tmp_path)  # no GeoLite2-City.mmdb here
    _reset_reader()

    assert geoip.lookup("8.8.8.8") == {}


def test_reader_is_cached_after_first_attempt(settings, tmp_path):
    settings.GEOIP_PATH = str(tmp_path)
    _reset_reader()

    geoip.lookup("8.8.8.8")
    assert geoip._reader_loaded is True
    assert geoip._get_reader() is None
