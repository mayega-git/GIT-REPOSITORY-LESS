import numpy as np
import hashlib

# Clé publique et privée

def less_keygen(k, n, q, seed):
    """
    Génère une paire de clés (publique et privée) pour le schéma LESS.

    :param k: Nombre de lignes de la matrice génératrice.
    :param n: Nombre de colonnes de la matrice génératrice.
    :param q: Taille du champ fini Fq.
    :param seed: Graine utilisée pour la génération des clés.
    :return: Clé privée (private_key) et clé publique (public_key).
    """
    np.random.seed(int(seed))  # Initialisation du générateur pseudo-aléatoire avec la graine

    # Clé privée : matrice privée de taille k x n, générée aléatoirement
    private_key = np.random.randint(0, q, size=(k, n))

    # Clé publique : matrice publique obtenue en multipliant la matrice privée par une matrice monomiale Q
    # Générer une matrice monomiale (Q) de taille n x n
    Q = np.eye(n, dtype=int)  # Matrice identité pour s'assurer de la compatibilité des dimensions
    public_key = np.dot(private_key, Q) % q  # Calcul de la matrice publique

    return private_key, public_key

# Paramètres de l'exemple
k = 4  # Nombre de lignes de la matrice génératrice
n = 6  # Nombre de colonnes de la matrice génératrice
q = 7  # Taille du champ fini Fq
seed = 42  # Graine pour la génération des clés

# Génération des clés
private_key, public_key = less_keygen(k, n, q, seed)

print("Clé privée :")
print(private_key)

print("\nClé publique :")
print(public_key)

def less_sign(private_key, message, salt, n, q, t):
    """
    Génère une signature pour un message donné en utilisant la clé privée et un défi.

    :param private_key: La clé privée (matrice privée).
    :param message: Le message à signer.
    :param salt: Un sel cryptographique pour garantir l'unicité.
    :param n: Nombre de colonnes de la matrice.
    :param q: Taille du champ fini Fq.
    :param t: Poids fixe du défi (nombre de bits non nuls).
    :return: Signature (salt, challenge, response, digest).
    """
    # Générer un défi aléatoire de taille n
    challenge = np.random.randint(0, q, size=(n, 1))

    # Calculer la réponse à ce défi en fonction de la clé privée
    response = np.dot(private_key, challenge) % q  # Réponse en fonction de la clé privée

    # Calculer le digest (hash) du message avec le sel et la réponse
    hash_input = salt + ''.join(map(str, response.flatten())) + message
    digest = hashlib.sha256(hash_input.encode()).hexdigest()  # Calcul du digest

    # Créer la signature avec le sel, le défi, la réponse et le digest
    signature = [salt, challenge.tolist(), response.tolist(), digest]

    return signature

# Paramètres de l'exemple
message = "Message à signer"
salt = "randomsalt"  # Sel cryptographique pour garantir l'unicité
t = 3  # Poids du défi
n = 6  # Nombre de colonnes dans la matrice
q = 7  # Taille du champ fini

# Générer la signature
signature = less_sign(private_key, message, salt, n, q, t)

print("Signature générée :")
print(signature)

def less_verify(public_key, signature, message, n, q):
    """
    Vérifie une signature LESS.

    :param public_key: Clé publique (matrice publique).
    :param signature: Signature à vérifier (salt, challenge, response, digest).
    :param message: Le message signé.
    :param n: Nombre de colonnes de la matrice publique.
    :param q: Taille du champ fini Fq.
    :return: True si la signature est valide, False sinon.
    """
    salt, challenge, response, digest = signature

    # Convert challenge back to numpy array
    challenge = np.array(challenge).reshape(n, 1)

    # Recalculer la réponse attendue à partir de la clé publique et du défi
    recalculated_response = np.dot(public_key, challenge) % q

    # Recalculer le digest
    hash_input = salt + ''.join(map(str, recalculated_response.flatten())) + message
    recalculated_digest = hashlib.sha256(hash_input.encode()).hexdigest()

    print("Digest original:", digest)
    print("Digest recalculé:", recalculated_digest)

    # Vérifier si le digest recalculé correspond à l'original
    if (recalculated_digest == digest):
       return True
    else:
       return False

# Vérification de la signature
//message = "Message à signer modifiee"
is_valid = less_verify(public_key, signature, message, n, q)
print("\nLa signature est valide :", is_valid)

