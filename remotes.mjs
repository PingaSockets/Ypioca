//remotes.js
import { execSync } from 'child_process';

// Prefixo para remotes
const PREFIXO_REMOTE = 'ups';
const upstreams = [
    "https://github.com/pst4r8/Baileys2023.git",
    "https://github.com/iamrony777/Baileys.git",
    "https://github.com/w3nder/Baileys.git",
    "https://github.com/bobslavtriev/Baileys.git",
    "https://github.com/devlikeapro/Baileys.git",
    "https://github.com/amiruldev20/Baileys.git",
    "https://github.com/renatoiub/Baileys.git",
    "https://github.com/EvolutionAPI/Baileys.git",
    "https://github.com/antoniocesar16/Baileys.git",
    "https://github.com/d0v3riz/Baileys.git",
    "https://github.com/makanSukros/Baileys.git",
    "https://github.com/Robson-pds/Baileys.git",
    "https://github.com/ozerbotai/Baileys.git",
    "https://github.com/DannOfficial/Baileys.git",
    "https://github.com/bluepepperok/Baileys.git",
    "https://github.com/qikerrs/Baileys.git",
    "https://github.com/ramon-victor/Baileys.git",
    "https://github.com/zeronumbergit/Baileys.git",
    "https://github.com/WhiskeySockets/Baileys.git"
];

// Adicionar ou atualizar remotes
upstreams.forEach((url) => {
    const remoteName = `${PREFIXO_REMOTE}-${url.split('/')[3]}`;
    try {
        console.log(`Configurando remote ${remoteName}...`);
        execSync(`git remote add ${remoteName} ${url}`, { stdio: 'ignore' });
    } catch {
        console.log(`Remote ${remoteName} já configurado.`);
    }
});
console.log('Configuração de remotes concluída.');
