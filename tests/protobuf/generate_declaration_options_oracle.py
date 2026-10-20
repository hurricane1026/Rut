"""Optional official protoc fixture; grpcio-tools==1.78.0 / protobuf==6.33.5."""
from pathlib import Path
import tempfile
from grpc_tools import protoc

root = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as temporary:
    output = Path(temporary) / "options.pb"
    result = protoc.main([
        "protoc", f"-I{root}", "--include_imports",
        f"--descriptor_set_out={output}", str(root / "declaration_options.proto"),
    ])
    if result:
        raise SystemExit(result)
    wire = output.read_bytes()
(root / "declaration_options_oracle.inc").write_text(
    "// Generated with official libprotoc 31.1.\n"
    "inline constexpr unsigned char kDeclarationOptionsDescriptor[] = {" + ", ".join(map(str, wire)) + "};\n"
)
