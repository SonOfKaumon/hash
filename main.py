
import hashlib
import hmac
import itertools
import string
import secrets


# 1. Criptografia por substituição (Cifra de César)
def criptografar(mensagem, chave):
    resultado = ""

    for caractere in mensagem:
        if caractere.isalpha() and caractere.isascii():
            base = ord("A") if caractere.isupper() else ord("a")
            novo = (ord(caractere) - base + chave) % 26 + base
            resultado += chr(novo)
        else:
            resultado += caractere

    return resultado


def descriptografar(mensagem, chave):
    return criptografar(mensagem, -chave)


# 2. Hash SHA-256
def gerar_hash(texto):
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


# 3. Hash seguro para demonstração de senhas
def criar_hash_senha(senha):
    salt = secrets.token_bytes(16)

    hash_senha = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        600_000
    )

    return salt.hex(), hash_senha.hex()


def verificar_senha(senha, salt_hex, hash_original):
    salt = bytes.fromhex(salt_hex)

    hash_teste = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        600_000
    )

    return hmac.compare_digest(hash_teste.hex(), hash_original)


# 4. Simulação controlada de força bruta
def simular_forca_bruta(senha_alvo, limite=100_000):
    caracteres = string.digits
    tentativas = 0

    for tamanho in range(1, len(senha_alvo) + 1):
        for combinacao in itertools.product(caracteres, repeat=tamanho):
            candidata = "".join(combinacao)
            tentativas += 1

            if candidata == senha_alvo:
                print("Senha encontrada:", candidata)
                print("Tentativas realizadas:", tentativas)
                return True

            if tentativas >= limite:
                print("Limite de tentativas atingido.")
                return False

    print("Senha não encontrada.")
    return False


# 5. Execução automática de todas as atividades
def main():
    print("=" * 45)
    print("PROJETO DE SEGURANÇA DA INFORMAÇÃO")
    print("=" * 45)

    # Criptografia
    mensagem = "Seguranca da informacao"
    chave = 3

    mensagem_cifrada = criptografar(mensagem, chave)
    mensagem_original = descriptografar(mensagem_cifrada, chave)

    print("\n1. CRIPTOGRAFIA")
    print("Mensagem original:", mensagem)
    print("Mensagem criptografada:", mensagem_cifrada)
    print("Mensagem descriptografada:", mensagem_original)

    # Hash de dados
    texto = "Exemplo de dados protegidos"
    hash_dados = gerar_hash(texto)

    print("\n2. HASH SHA-256")
    print("Texto:", texto)
    print("Hash:", hash_dados)

    # Hash e verificação de senha
    senha_teste = "SenhaTeste123!"
    salt, hash_senha = criar_hash_senha(senha_teste)

    print("\n3. SEGURANÇA DE SENHAS")
    print("Salt gerado:", salt)
    print("Hash da senha:", hash_senha)
    print("Senha correta:", verificar_senha(
        senha_teste, salt, hash_senha
    ))
    print("Senha incorreta:", verificar_senha(
        "senhaErrada", salt, hash_senha
    ))

    # Força bruta: senha numérica fictícia e curta
    print("\n4. SIMULAÇÃO DE FORÇA BRUTA")
    simular_forca_bruta("123", limite=100_000)

    # Condicionais e repetições
    print("\n5. CONDICIONAIS E REPETIÇÕES")
    notas_seguranca = [4, 7, 9]

    for nota in notas_seguranca:
        if nota < 5:
            situacao = "Segurança fraca"
        elif nota < 8:
            situacao = "Segurança moderada"
        else:
            situacao = "Segurança forte"

        print(f"Nível {nota}: {situacao}")

    # Boas práticas
    print("\n6. BOAS PRÁTICAS DE SEGURANÇA")

    boas_praticas = [
        "Utilizar senhas longas e exclusivas.",
        "Ativar autenticação multifator.",
        "Nunca armazenar senhas em texto puro.",
        "Usar Argon2id, scrypt ou PBKDF2 para senhas.",
        "Atualizar sistemas e bibliotecas.",
        "Limitar tentativas de autenticação.",
        "Fazer backups e restringir acessos."
    ]

    for pratica in boas_praticas:
        print("-", pratica)

    print("\nTodas as atividades foram executadas.")


if __name__ == "__main__":
    main()
