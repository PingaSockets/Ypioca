// squash-remotes.mjs
import { execSync } from 'child_process';

// Definindo constante para as branches remotas
const BRANCH_REMOTE = ["master", "main"]; // Adicionar ou remover branches facilmente
const BRANCH_LOCAL = 'scrapy'; // Branch local que vai receber todas as alterações remotas
const UPSTREAM_PREFIXO = "ups-";

// Função para rodar comandos Git
function executarComandoGit(comando) {
    try {
        return execSync(comando, { stdio: 'pipe' }).toString().trim();
    } catch (erro) {
        throw new Error(`Erro ao executar comando Git: ${erro}`);
    }
}

// Função para fazer o fetch e merge da branch local com as branches remotas
function mesclarScrapyComRemotas() {
	console.log(`Iniciando o fetch e merge dos remotes...`);
    // Obter todos os remotes configurados
    const remotes = executarComandoGit('git remote').split('\n').map(r => r.trim());

    // Filtrar apenas os remotes upstream (remotes que começam com o prefixo)
    const upstreams = remotes.filter(remote => remote.startsWith(UPSTREAM_PREFIXO));

	// Fazer fetch de todos os upstreams	
	try {
		executarComandoGit('git fetch --all');
	} catch (erro) {
		console.log(`Erro ao fazer fetch: ${erro.message}`);
		process.exit(1);
	}

	// Fazendo o merge da branch remota com a branch local
	upstreams.forEach(upstream => {
		try {
			// Verificando se o remote está acessível
			const existeRemote = executarComandoGit(`git remote get-url ${upstream}`);
			if (existeRemote) {
				// Fazendo o merge da branch remota com a branch local
				BRANCH_REMOTE.forEach(branch => {
					if (verificarBranchRemotaExiste(upstream, branch)) {
						console.log(`Mesclando alterações da branch remota '${branch}' na branch local '${BRANCH_LOCAL}'...`);
						// Mesclando com squash, para apenas obter as mudanças e não fazer commit sem antes testar o código
						executarComandoGit(`git merge --squash ${upstream}/${branch}`);
					} else {
						console.log(`Branch remota '${branch}' não encontrada no upstream ${upstream}...`);
					}
				});

				console.log('Mesclagens concluídas com sucesso.');

			}
		} catch (erro) {
			// Se não encontrar o remote ou ocorrer qualquer erro, ignorar e continuar
			console.log(`Erro ao fazer merge do remote ${upstream}: ${erro.message}`);
		}
	});
	console.log(`Finalizado o merge dos remotes!`);
}

function verificarBranchRemotaExiste(upstream, branchRemota) {
    try {
        // Verificando se a branch remota existe        
		executarComandoGit(`git show-ref refs/remotes/${upstream}/${branchRemota}`);
        return true; // Branch existe
    } catch (erro) {
        return false; // Branch não existe
    }
}

// Executando o script
try {
    console.log('Iniciando o processo...');
    
    // Passo 1: Trocar para a branch principal
    console.log('Trocando para a branch principal (main)...');
    executarComandoGit('git checkout main'); // Aqui, alteramos para a branch principal

    // Passo 2: Buscar as alterações do repositório upstream principal
    console.log('Buscando as últimas alterações do upstream principal...');
    executarComandoGit('git fetch https://github.com/WhiskeySockets/Baileys.git'); // repositório principal
    
    // Passo 3: Voltar para a branch local onde será feito o merge
    console.log('Voltando para a branch local (scrapy)...');
    executarComandoGit(`git checkout ${BRANCH_LOCAL}`); // Retorna para a branch local "scrapy"
    
    // Passo 4: Mesclar as mudanças da branch local com as remotas
    console.log('Tentando mesclar com os remotes...');
    mesclarScrapyComRemotas(); // Aqui o merge com remotes secundários acontece, com squash

} catch (erro) {
    console.error('Erro:', erro.message); // Caso ocorra algum erro, exibe a mensagem
}
