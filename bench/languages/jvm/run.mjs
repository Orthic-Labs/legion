// JVM language bench: wrapper-first command selection and framework pack
// observations.
import jvmPack from '../../../providers/native/jvm/index.mjs';
import springPack from '../../../providers/frameworks/spring/index.mjs';
import ktorPack from '../../../providers/frameworks/ktor/index.mjs';

const gradle = jvmPack.commands({ root: '/repo', files: ['A.java'], manifests: ['build.gradle'], profile: 'standard' });
const maven = jvmPack.commands({ root: '/repo', files: ['A.java'], manifests: ['pom.xml'], profile: 'standard' });
const springObs = springPack.analyze({ files: ['C.java'], readFile: () => 'http.csrf(csrf -> csrf.disable())' }).length;
const ktorObs = ktorPack.analyze({ files: ['App.kt'], readFile: () => 'install(CORS) { anyHost() }' }).length;

console.log(`jvm bench: gradle=${gradle.length}, maven=${maven.length}, spring=${springObs}, ktor=${ktorObs}`);
if (!gradle.length || !maven.length) process.exit(1);
if (springObs < 1 || ktorObs < 1) process.exit(1);
console.log('GATE: PASS');
