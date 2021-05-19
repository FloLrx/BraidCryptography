def inverse_tresse(t):# tresses sous forme de listes, calcule l'inverse d'une tresse
    t2=[]
    n=len(t)
    for i in range(n):
        t2.append(-t[n-1-i])
    return t2
##
def produit_tresse(t1,t2):# tresses sous forme de listes, calcule le produit entre deux tresses
    return t1+t2
##
def liste_a_str(l):# transforme une liste en str
    s=""
    for i in l:
        s=s+str(i)
    return s
##
def somme_en_base_2(a,b):# str de meme taille
    s=""
    for i in range(len(a)):
        c=int(a[i])+int(b[i])
        if c==0 or c==2:
            s=s+'0'
        else:
            s=s+'1'
    return s
##
def latin_a_binaire(m):# transforme un mot en sa représentation en code ASCII
    m2=""
    for i in m:
        j=bin(ord(i))[2:]
        for k in range(8-len(j)):# chaque lettre de m est représentée par 8 bits
            j="0"+j
        m2=m2+j
    return m2
##
def binaire_a_latin(m):# transforme un mot écrit en binaire en français par le code ASCII
    m2=""
    while len(m)!=0:
        i=int(m[:8],2)
        m2=m2+chr(i)
        m=m[8:]
    return m2
##
def decoupage(m,n):# découpe m en messages de taille n
    L=[]
    for i in range(int(len(m)/n)):
        L.append(m[i*n:(i+1)*n])
    a=m[int(len(m)/n)*n:]
    while len(a) != n:
        a=a+latin_a_binaire(" ")
    L.append(a)
    return L
##
def concatene(Lm): # liste des mots, concatène les mots de Lm en un seul mot
    m=""
    for i in Lm:
        m=m+i
    return m
##
import hashlib
import numpy as np
##
def cryptage(m,x,a,b):# tresses sous forme de listes, message en str, crypte un message écrit en binaire, retourne une liste de sous-messages cryptés car besoin que messages aient même taille que clé
    inv_a=inverse_tresse(a)
    inv_b=inverse_tresse(b)
    pb=produit_tresse(produit_tresse(b,x),inv_b)# tresses sous forme de listes
    K=liste_a_str(produit_tresse(produit_tresse(a,pb),inv_a))# clé en str
    K_hc=hashlib.blake2s(np.array(K)).hexdigest()# clé hachée en str en hexadéc
    K_fin=bin(int(K_hc,16))[2:]# clé presque finale, ie hachée et en binaire mais pas forcément bonne taille
    while len(K_fin)!=256:# met clé à la bonne taille
        K_fin='0'+K_fin
    n=len(K_fin)# on va découper en sous-messages de cette taille
    M=latin_a_binaire(m)
    Lm=decoupage(M,n)# liste de sous-messages
    Lmc=[]# future liste de sous-messages cryptés
    for i in Lm:# cryptage
        Lmc.append(somme_en_base_2(K_fin,i))
    return Lmc
##
def decryptage(Lmc,x,a,b):# tresses sous forme de listes, liste de sous-messages en str, renvoie le message décrypté en binaire
    inv_a=inverse_tresse(a)
    inv_b=inverse_tresse(b)
    pb=produit_tresse(produit_tresse(b,x),inv_b)# tresses sous forme de listes
    K=liste_a_str(produit_tresse(produit_tresse(a,pb),inv_a))# clé en str
    K_hc=hashlib.blake2s(np.array(K)).hexdigest()# clé hachée en str en hexadéc
    K_fin=bin(int(K_hc,16))[2:]# clé presque finale, ie hachée et en binaire mais pas forcément bonne taille
    while len(K_fin)!=256:# met clé à la bonne taille
        K_fin='0'+K_fin
    Lm=[]# future liste de sous-messages décryptés
    for i in Lmc:# décryptage
        Lm.append(somme_en_base_2(K_fin,i))
    M=concatene(Lm)# message décrypté en binaire
    m=binaire_a_latin(M)# message décrypté final
    return m