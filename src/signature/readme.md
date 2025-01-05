# BBS signatures

## Global common parameters

Let $\lambda$ be the security parameter. Let $(\mathbb{G}_1,\mathbb{G}_2)$ be a bilinear group pair such that $|\mathbb{G}_1|=|\mathbb{G}_2|=p$ for some prime $p$ of $\lambda$ bits.

Let $g_1, h_1, \dots, h_\ell$ be generators of $\mathbb{G}_1$, and $g_2$ be a generator of $\mathbb{G}_2$.

## Key generation

Randomly sample $\gamma\gets_\$\mathbb{Z}_p^*$, and compute $w:=g_2^\gamma$.

Then the secret key is $\mathsf{sk}:=\gamma$, and the verification key is $\mathsf{vk}:=w$.

## Signing block of messages

On input $(m_1,\dots,m_\ell)\in\mathbb{Z}_p^\ell$, sample $e\gets_\$\mathbb{Z}_p^*$, then compute:
$$
B := g_1\cdot \prod_{i=1}^\ell h_i^{m_i},
$$
and then,
$$
A := B^{1/(\mathsf{sk} + e)}.
$$

Return $\sigma=(A, e)$ as the signature.

## Verifying signature

To verify a signature $(A, e)$ on $(m_1,\dots,m_\ell)$, check if:
$$
e\left(A, \mathsf{vk}\cdot g_2^e\right)
\overset{?}{=}
e\left(g_1\cdot \prod_{i=1}^\ell h_i^{m_i}, g_2\right).
$$
