import eslintConfigPingasockets from '@pingasockets/eslint-config'
import globals from 'globals'

export default [
    // Extensão da configuração base
    ...eslintConfigPingasockets,

    // Configuração adicional específica do projeto
    {
        files: ['**/*.ts'], // Aplica a configuração a arquivos TypeScript
        languageOptions: {
            ecmaVersion: 'latest', // Define a versão do ECMAScript
            sourceType: 'module', // Define que o código usa módulos ES
            globals: {
                ...globals.es2023 // Inclui globais do ES2023
            },
            parser: '@typescript-eslint/parser', // Define o parser TypeScript
            parserOptions: {
                project: './tsconfig.json' // Define o caminho do tsconfig.json
            }
        }
    }
]

/**
module.exports = {
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
      {*/
        //files: ['src/**/*.{js,ts}'] // Lint all JavaScript and TypeScript files in src and subdirectories
        /**
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
*/