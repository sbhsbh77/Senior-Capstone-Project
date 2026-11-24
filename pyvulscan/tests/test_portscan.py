import time

from labs.weak_target import start_web
from pyvulscan.portscan import scan


def test_open_port_is_detected_with_banner():
    httpd = start_web(port=0)
    port = httpd.server_address[1]
    try:
        time.sleep(0.4)
        results = scan("127.0.0.1", ports=[port], timeout=1.0)
        assert len(results) == 1
        assert results[0].status == "open"
        assert "HTTP/1" in results[0].banner
    finally:
        httpd.shutdown()
