### By: Starglow {#by-starglow .unnumbered}

### View original at: [starglow.net/blog/ctf/prime-sponsorship](https://starglow.net/blog/ctf/prime-sponsorship/) {#view-original-at-starglow.netblogctfprime-sponsorship .unnumbered}

# Description

Here we're given the following: $$$$ crypto/prime-sponsorship $$$$
\"Welcome to your PRIME. Where great flavor meets function. Zero Added
Sugar. 10% Coconut Water. BCAAs, Electrolytes, Antioxidants, Lattices,
and more.\" $$$$ with output.txt and gen.sage, both given in the
appendix.

# Solution

To solve, we work in the
[ring](https://en.wikipedia.org/wiki/Ring_(mathematics)):
$$R_{q,p}=\mathbf F_{q}[x]/\bigl(x^{p}-x-1\bigr),
\qquad q=1511,p\in\{211,223\}$$ where two ternary (coefficients
$\in {-1,0,1}$) polynomials $f,g\in\mathbf Z[x]$ of degree $<p_1=211$
are chosen such that $g\bmod 3$ is invertible in $R_{3,211}$ and
$R_{3,223}$. For each prime length $p\in\{211,223\}$:
$$h_p = g(3f)^{-1}\pmod{(q,x^{p}-x-1)}$$ which means one pair $(f,g)$ is
reused in two different rings. For encryption, the plaintext is a binary
vector $r\in\{0,1\}^{211}$:
$$c=\operatorname{Round}_3\!\bigl(h_{211}\,r\bigr)$$ where
$\operatorname{Round}_3$ moves every coefficient to the nearest multiple
of 3. To decrypt, $e=(3f)\,c,$ we lift the coefficients to
$(-\!q/2,q/2]$ and output $g^{-1}e\bmod 3$. Because $3f\,h_{211}=g$ this
cancels and returns $r$. This is fatal, since over the product ring
$R_{q,211}\times R_{q,223}$ we know the two residues
$$H=(h_{211},h_{223}) =\frac{g}{3f}$$ so writing the moduli as
$\phi_{211}=x^{211}-x-1$ and $\phi_{223}=x^{223}-x-1$ the [Chinese
Remainder
Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem) lets
us view $H$ as one element of:
$$R_q=\mathbf F_q[x]/(\phi_{211}\phi_{223})$$ and what's important to
notice is that in $\deg f,\deg g<211$ both $g$ and $3f$ are much smaller
than the combined $\phi_{211}\phi_{223}$ (of degree 434). Recovering a
small numerator/denominator from their ratio modulo a large polynomial
is called a [rational reconstruction
problem](https://en.wikipedia.org/wiki/Rational_reconstruction_(mathematics)).

Now we need to turn this idea into linear algebra. We write the
convolution-by-$h$ operator in matrix form where we let
$C_{211},C_{223}$ be the $211\times211$ and $223\times211$ matrices
representing multiplication by $h_{211}$, $h_{223}$. So from the
definition of the public keys we have two linear relations:
$$3\,C_{211}\,f-g\equiv0\pmod{q\,,\phi_{211}}$$ and:
$$3\,C_{223}\,f-g\equiv0\pmod{q\,,\phi_{223}}$$ so we restrict the
second congruence to the first 211 coefficients and subtract. This kills
$g$ and gives us one homogeneous system over $\mathbf F_{1511}$:
$$D\,f=0,\qquad
D = 3\bigl(C_{211}-C_{223}^{\small\text{(cut)}}\bigr)
(\bmod 1511)$$ where $D$ is a $211\times211$ matrix. Then, a quick
modular Gaussian elimination shows that $\dim\kern.5pt\ker D = 1$. This
means the nullspace immediately gives (up to a unit) the unique ternary
vector $f$. All its coefficients therefore lie in $\{-1,0,1\}$which
confirms we found what we wanted. Now with $f$ known:
$$g = 3f\,h_{211}\pmod{(1511,\phi_{211})}$$ will have the same ternary
property.

Finally we need to get the last missing part, $g^{-1}\bmod 3$. Instead
of an expensive Euclidean inverse inside a big polynomial ring we can
solve the much smaller linear system:
$$\bigl(\text{conv}(g\bmod 3)\bigr)\,x = (1,0,\dots,0)
\quad\text{over }\mathbf F_{3}$$ which is the same as inverting
$g\bmod 3$ by plain Gaussian elimination in$\mathbf F_3^{211\times211}$,
which will return $g^{-1}\bmod 3$. Now for decrypting the given
ciphertext we:

1.  $e = (3f)\,c \pmod{(1511,\phi_{211})}$

2.  lift each coefficient of $e$ to $(-755,755]$

3.  find $m = g^{-1}e\bmod 3$

which means each entry of $m$ is 0 or 1 which gives us a 211-bit string:

    110111011101100111010110010110001110100110001011100110000101001111001110010101...

and converting to bytes (and undoing the $[7:-2]$ slicing the challenge
code performs) gives us:

    b'no_logan_paul_here'

which gives us the flag:

    UMDCTF{no_logan_paul_here}

# Appendix {#sec:append}

Credit: aparker

## gen.sage

    import random
    from Crypto.Util.number import bytes_to_long, long_to_bytes
    from sage.arith.misc import crt

    p1 = 211
    p2 = 223
    q = 1511

    # strip UMDCTF{}\n
    flag = open('flag.txt', 'rb').read()[7:-2]

    def encode(msg):
        m = bin(bytes_to_long(msg))[2:].zfill(p1)
        return [0 if c == '0' else 1 for c in m]


    Fq = GF(q)
    F3 = GF(3)
    Rq = PolynomialRing(Fq, 'x').quotient(x^p1 - x - 1)
    R3 = PolynomialRing(F3, 'x').quotient(x^p1 - x - 1)

    Rq_2 = PolynomialRing(Fq, 'x').quotient(x^p2 - x - 1)
    R3_2 = PolynomialRing(F3, 'x').quotient(x^p2 - x - 1)

    Rx.<x> = PolynomialRing(ZZ, 'x')
    Qx = PolynomialRing(QQ, 'x')

    # keygen
    h1, h2 = None, None
    g_inv, f = None, None
    while True:
        g = Rx([random.choice([-1,0,1]) for _ in range(p1)])
        g3 = R3(g)
        g3_2 = R3_2(g)
        if g3.is_unit() and g3_2.is_unit():
            g_inv = g3.inverse()
            f = Rx([random.choice([-1,0,1]) for _ in range(p1)])
            h1 = Rq(g) / Rq(3 * f)
            h2 = Rq_2(g) / Rq_2(3 * f)
            break

    def round3(poly):
        new_poly = []
        for c in poly.list():
            c = ZZ(c)
            if c % 3 == 1:
                new_poly.append(c - 1)
            elif c % 3 == 0:
                new_poly.append(c)
            else:
                new_poly.append(c+1)
        return Rq(new_poly)


    def encrypt(r):
        return round3(h1 * Rq(r))

    def decrypt(ct, f, g_inv):
        e = Rq(3 * f) * ct
        e = [c.lift_centered() for c in e]
        print("e = ", e)
        return list(g_inv * R3(e))


    print("With our new PRIME sponsorship, we bundled an extra public key for you*!")
    print()

    print("pk1 =", h1.list())
    print("pk2 =", h2.list())

    msg = encode(flag)
    ct1 = encrypt(msg)

    print("ct =", ct1.list())

    print("*ciphertext not included")

## output.txt

    With our new PRIME sponsorship, we bundled an extra public key for you*!
    pk1 = [1475, 724, 857, 322, 1405, 898, 1406, 1299, 41, 745, 500, 1382, 196, 77, 882, 25, 774, 293, 135, 961, 1431, 675, 1246, 940, 106, 1286, 1065, 586, 1497, 702, 1213, 900, 246, 282, 1080, 916, 532, 369, 708, 257, 1345, 469, 395, 250, 691, 1216, 819, 566, 56, 1500, 25, 1428, 1104, 262, 537, 253, 1163, 202, 358, 620, 1304, 321, 369, 97, 451, 1122, 624, 441, 1489, 499, 590, 524, 446, 85, 435, 1493, 912, 56, 987, 1076, 439, 829, 66, 177, 113, 491, 644, 894, 732, 503, 112, 1365, 1359, 636, 28, 400, 207, 175, 861, 128, 1087, 945, 582, 14, 778, 1419, 1362, 53, 1208, 84, 1189, 680, 419, 297, 1414, 768, 1506, 1263, 948, 1055, 1007, 385, 837, 195, 1058, 1007, 678, 1007, 696, 1033, 373, 1240, 127, 806, 115, 322, 434, 651, 152, 1180, 911, 868, 1241, 1091, 1469, 440, 204, 719, 1251, 1090, 585, 998, 800, 1057, 1383, 1026, 1349, 51, 1405, 1378, 156, 1473, 413, 1402, 1481, 1488, 680, 31, 516, 87, 1066, 1142, 784, 968, 1120, 987, 676, 1315, 314, 1011, 462, 124, 435, 130, 1486, 331, 706, 509, 1119, 1475, 235, 600, 1143, 460, 874, 274, 351, 1184, 840, 974, 1094, 259, 1090, 1419, 872, 639, 1112, 1313, 263, 1134, 1156]
    pk2 = [1045, 277, 193, 978, 65, 1224, 1109, 513, 1351, 799, 454, 325, 163, 493, 392, 469, 549, 315, 1110, 759, 359, 85, 541, 744, 165, 1256, 1258, 1414, 31, 116, 230, 947, 1449, 1439, 400, 918, 838, 168, 47, 1325, 702, 610, 1391, 164, 602, 176, 309, 70, 965, 1159, 1016, 231, 1278, 143, 1271, 1383, 1014, 567, 290, 1263, 879, 701, 1310, 443, 713, 1456, 236, 317, 1056, 1159, 1181, 1218, 866, 87, 323, 435, 851, 1216, 1502, 376, 1127, 1454, 1281, 1158, 17, 320, 63, 1161, 1024, 877, 283, 399, 196, 659, 939, 307, 529, 176, 1458, 484, 372, 384, 103, 180, 955, 695, 502, 1456, 945, 914, 389, 249, 1013, 560, 1483, 769, 1089, 264, 753, 1047, 163, 1169, 567, 393, 924, 1473, 402, 519, 963, 1002, 1354, 1248, 91, 67, 1447, 320, 298, 791, 20, 889, 1266, 686, 139, 1417, 960, 963, 66, 26, 128, 591, 689, 1437, 450, 589, 485, 875, 1296, 1482, 350, 323, 1104, 322, 458, 1079, 719, 330, 578, 513, 128, 1322, 886, 1096, 1074, 300, 882, 428, 608, 1250, 1497, 30, 785, 1408, 846, 108, 1043, 619, 465, 1249, 942, 1264, 1219, 843, 459, 1486, 236, 1238, 442, 488, 111, 153, 120, 457, 4, 251, 445, 580, 1276, 581, 1188, 1180, 1345, 1045, 458, 430, 580, 119, 871, 766, 1164, 851, 1182, 53, 1183]
    ct = [1017, 1506, 117, 123, 1458, 582, 1491, 1383, 1107, 438, 1263, 825, 1299, 387, 717, 21, 114, 1251, 177, 1338, 192, 102, 141, 9, 459, 669, 381, 369, 144, 459, 759, 1215, 1440, 612, 1305, 1152, 78, 321, 1227, 918, 540, 780, 873, 999, 876, 228, 1041, 852, 1188, 348, 1146, 1257, 975, 33, 1068, 195, 1227, 300, 36, 834, 1227, 540, 168, 690, 1107, 561, 492, 1107, 489, 915, 1191, 129, 144, 249, 186, 519, 1437, 1485, 1332, 852, 288, 123, 1092, 291, 57, 855, 810, 390, 273, 327, 60, 195, 489, 735, 1476, 549, 645, 642, 1434, 768, 789, 108, 1095, 66, 117, 1458, 1233, 846, 891, 594, 447, 117, 306, 339, 1179, 546, 1377, 237, 444, 1242, 1470, 1101, 1200, 345, 1449, 330, 663, 282, 24, 288, 354, 657, 447, 384, 1200, 66, 1332, 138, 1242, 915, 729, 1320, 702, 876, 519, 156, 1179, 993, 378, 1044, 816, 243, 1158, 630, 429, 1416, 516, 720, 852, 1098, 264, 855, 1434, 21, 1032, 822, 60, 669, 681, 465, 30, 972, 873, 837, 687, 1173, 516, 864, 906, 387, 981, 999, 1362, 393, 1347, 48, 528, 738, 1353, 630, 801, 144, 114, 1506, 405, 573, 1008, 246, 1020, 888, 1386, 1458, 1482, 195, 1437, 1164, 1464, 270, 1509, 1071, 987]
    *ciphertext not included