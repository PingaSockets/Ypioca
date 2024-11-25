/** @type {import('eslint').Linter.Config} */
module.exports [
  {
    extends: '@pingasockets',
    parserOptions: {
      sourceType: 'module',
      project: './tsconfig.json'
    },
    rules: {
      '@typescript-eslint/no-explicit-any': [
        'warn',
        {
          ignoreRestArgs: true
        }
      ],
      '@typescript-eslint/no-inferrable-types': ['warn'],
      '@typescript-eslint/no-redundant-type-constituents': ['warn'],
      '@typescript-eslint/no-unnecessary-type-assertion': ['warn'],
      'no-restricted-syntax': 'off',
      'keyword-spacing': ['warn'],
      'linebreak-style': ['off'] // adicionado porque uso windows
    },
    overrides: [
      {
        files: ['src/**/*.{js,ts}'] // Lint all JavaScript and TypeScript files in src and subdirectories
      }
    ]
  },
    {
    ignores: [
      "lib/**",           // Ignora toda a pasta lib e seus arquivos
      "coverage/**",      // Ignora toda a pasta coverage e seus arquivos
      "*.lock",           // Ignora arquivos de lock
      "WAProto/**",       // Ignora toda a pasta WAProto
      "WASignalGroup/**",  // Ignora toda a pasta WASignalGroup
	], 
  }
];