// Go language bench: command selection and framework observations.
import goPack from '../../../providers/native/go/index.mjs';
import goWebPack from '../../../providers/frameworks/go-web/index.mjs';
import grpcPack from '../../../providers/frameworks/grpc/index.mjs';

const commands = goPack.commands({ root: '/repo', files: ['main.go'], manifests: ['go.mod'], profile: 'standard' });
const webObs = goWebPack.analyze({ files: ['main.go'], readFile: () => 'srv := &http.Server{Addr: ":8080"}\ncmd := exec.Command("sh", r.FormValue("c"))' }).length;
const grpcObs = grpcPack.analyze({ files: ['api.proto'], readFile: () => 'service S { rpc Get(Req) returns (Res); }' }).length;

console.log(`go bench: ${commands.length} commands, web=${webObs}, grpc=${grpcObs}`);
if (commands.length < 3) process.exit(1);
if (webObs < 2 || grpcObs < 1) process.exit(1);
console.log('GATE: PASS');
