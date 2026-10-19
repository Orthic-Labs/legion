import parser from '@typescript-eslint/parser';
export default [{files:['**/*.{js,cjs,mjs,ts,cts,mts,jsx,tsx}'],languageOptions:{parser,parserOptions:{ecmaVersion:2022,sourceType:'module',ecmaFeatures:{jsx:true}}},rules:{'no-debugger':'error'}}];
