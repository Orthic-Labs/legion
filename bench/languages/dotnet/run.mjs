// .NET language bench: build/test command selection and framework observations.
import dotnetPack from '../../../providers/native/dotnet/index.mjs';
import aspnetPack from '../../../providers/frameworks/aspnet/index.mjs';
import efPack from '../../../providers/frameworks/entity-framework/index.mjs';

const commands = dotnetPack.commands({ root: '/repo', files: ['A.cs'], manifests: ['App.csproj'], profile: 'standard' });
const aspnetObs = aspnetPack.analyze({ files: ['Program.cs'], readFile: () => 'app.UseCors(b => b.AllowAnyOrigin())' }).length;
const efObs = efPack.analyze({ files: ['Repo.cs'], readFile: () => 'db.Users.FromSqlRaw($"SELECT * FROM Users")' }).length;

console.log(`dotnet bench: ${commands.length} commands, aspnet=${aspnetObs}, ef=${efObs}`);
if (commands.length < 2) process.exit(1);
if (aspnetObs < 1 || efObs < 1) process.exit(1);
console.log('GATE: PASS');
