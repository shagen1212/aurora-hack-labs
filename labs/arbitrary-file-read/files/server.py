import io
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


def build_archive():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(
            "ziptest/metrics.csv",
            "metric,q1_actual,q2_target\nRevenue,2.1M,5M\nChurn,5.2%,3%\n",
        )
        bundle.writestr("ziptest/environ.link", "/etc/hostname")
        bundle.writestr("ziptest/status.link", "/etc/os-release")
    with open("/srv/data.zip", "wb") as archive:
        archive.write(buffer.getvalue())


build_archive()
ThreadingHTTPServer(("0.0.0.0", 8000), SimpleHTTPRequestHandler).serve_forever()
