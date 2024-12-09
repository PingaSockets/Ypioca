// eslint.config.js
import sharedConfig from '@pingasockets/eslint-config-ypioca';

export default [
  ...sharedConfig,

 //regras personalizadas deste projeto 
  {
	rules: {
		"no-restricted-syntax": "off"
	}
},  
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: {
        project: './tsconfig.json',
        //tsconfigRootDir: __dirname,
      }
    }
  },

  // Ignorar pastas e padrões de arquivos
  {
    ignores: [
      "docs/**",
      "lib/**",
      "coverage/**",
      "*.lock",
      "WAProto/**",
      "WASignalGroup/**",
      "src/Tests/**", // why?
	  "Example/**", // bug
	  "eslint.config.js", // bug
	  "jest.config.js", // bug
	  "proto-extract/**", // bug
    ]
  }
];