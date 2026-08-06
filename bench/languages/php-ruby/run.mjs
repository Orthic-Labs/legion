// PHP/Ruby language bench: command selection and framework observations.
import phpPack from '../../../providers/native/php/index.mjs';
import rubyPack from '../../../providers/native/ruby/index.mjs';
import laravelPack from '../../../providers/frameworks/laravel/index.mjs';
import railsPack from '../../../providers/frameworks/rails/index.mjs';

const phpCommands = phpPack.commands({ root: '/repo', files: ['a.php'], manifests: ['composer.json'], profile: 'standard' });
const rubyCommands = rubyPack.commands({ root: '/repo', files: ['a.rb'], manifests: ['Gemfile'], profile: 'standard' });
const laravelObs = laravelPack.analyze({ files: ['c.php'], readFile: () => 'DB::select("SELECT * FROM x WHERE id = $id")' }).length;
const railsObs = railsPack.analyze({ files: ['c.rb'], readFile: () => 'skip_forgery_protection' }).length;

console.log(`php-ruby bench: php=${phpCommands.length}, ruby=${rubyCommands.length}, laravel=${laravelObs}, rails=${railsObs}`);
if (phpCommands.length < 3 || rubyCommands.length < 3) process.exit(1);
if (laravelObs < 1 || railsObs < 1) process.exit(1);
console.log('GATE: PASS');
