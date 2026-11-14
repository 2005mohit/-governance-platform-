from flask import jsonify
import traceback
def fail(e):
    return jsonify({"error": traceback.format_exc()})
