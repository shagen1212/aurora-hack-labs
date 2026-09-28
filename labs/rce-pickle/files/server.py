import pickle
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class TrainingModel:
    def __reduce__(self):
        return (eval, ("'controlled-pickle-execution'",))


with open("/srv/metrics.csv", "w") as metrics:
    metrics.write("metric,value\nrevenue,250\nchurn,75\n")

with open("/srv/model.pkl", "wb") as model:
    pickle.dump(TrainingModel(), model)

ThreadingHTTPServer(("0.0.0.0", 8000), SimpleHTTPRequestHandler).serve_forever()
