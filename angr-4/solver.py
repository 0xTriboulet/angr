#!/usr/bin/env python
import angr
import monkeyhex

'''
_a = [-43, 61, 58, 5, -4, -11, 64, -40, -43, 61, 62, -51, 46, 15, -49, -44, 47, 4, 6, -7, 47, 7, -59, 52, -15, 11, 7, 61]
_b = [6, 106, 10, 0, 119, 52, 51, 101, 0, 0, 15, 48, 116, 22, 10, 58, 125, 100, 102, 33]
_c = [304, 357, 303, 320, 304, 307, 349, 305, 257, 337, 340, 309, 428, 270, 66]
'''

proj = angr.Project('/bin/true')
state = proj.factory.entry_state()

a = state.solver.BVS("a",64)
b = state.solver.BVS("b",64)
c = state.solver.BVS("c",64)
d = state.solver.BVS("d",64)

state.solver.add(a-b == -43)
state.solver.add(c-d == 61)
state.solver.add(a^b^c == 6)
state.solver.add(a+b+c+d == 304)

state.solver.add(a >= 32)
state.solver.add(b >= 32)
state.solver.add(c >= 32)
state.solver.add(d >= 32)

state.solver.add(a <= 126)
state.solver.add(b <= 126)
state.solver.add(c <= 126)
state.solver.add(d <= 126)




e = state.solver.BVS("e",64)
f = state.solver.BVS("f",64)
g = state.solver.BVS("g",64)
h = state.solver.BVS("h",64)

state.solver.add(e-f == 58)
state.solver.add(g-h == 5)
state.solver.add(d^e^f == 106)
state.solver.add(e+f+g+h == 357)

state.solver.add(e >= 32)
state.solver.add(f >= 32)
state.solver.add(g >= 32)
state.solver.add(h >= 32)

state.solver.add(e <= 126)
state.solver.add(f <= 126)
state.solver.add(g <= 126)
state.solver.add(h <= 126)




i = state.solver.BVS("i",64)
j = state.solver.BVS("j",64)
k = state.solver.BVS("k",64)
l = state.solver.BVS("l",64)

state.solver.add(i-j == -4)
state.solver.add(k-l == -11)
state.solver.add(g^h^i == 10)
state.solver.add(i+j+k+l == 303)

state.solver.add(i >= 32)
state.solver.add(j >= 32)
state.solver.add(k >= 32)
state.solver.add(l >= 32)

state.solver.add(i <= 126)
state.solver.add(j <= 126)
state.solver.add(k <= 126)
state.solver.add(l <= 126)






m = state.solver.BVS("m",64)
n = state.solver.BVS("n",64)
o = state.solver.BVS("o",64)
p = state.solver.BVS("p",64)

state.solver.add(m-n == 64)
state.solver.add(o-p == -40)
state.solver.add(j^k^l == 0)
state.solver.add(m+n+o+p == 320)

state.solver.add(m >= 32)
state.solver.add(n >= 32)
state.solver.add(o >= 32)
state.solver.add(p >= 32)

state.solver.add(m <= 126)
state.solver.add(n <= 126)
state.solver.add(o <= 126)
state.solver.add(p <= 126)






q = state.solver.BVS("q",64)
r = state.solver.BVS("r",64)
s = state.solver.BVS("s",64)
t = state.solver.BVS("t",64)

state.solver.add(q-r == -43)
state.solver.add(s-t == 61)
state.solver.add(m^n^o == 119)
state.solver.add(q+r+s+t == 304)

state.solver.add(q >= 32)
state.solver.add(r >= 32)
state.solver.add(s >= 32)
state.solver.add(t >= 32)

state.solver.add(q <= 126)
state.solver.add(r <= 126)
state.solver.add(s <= 126)
state.solver.add(t <= 126)






u = state.solver.BVS("u",64)
v = state.solver.BVS("v",64)
w = state.solver.BVS("w",64)
x = state.solver.BVS("x",64)

state.solver.add(u-v == 62)
state.solver.add(w-x == -51)
state.solver.add(p^q^r == 52)
state.solver.add(u+v+w+x == 307)

state.solver.add(u >= 32)
state.solver.add(v >= 32)
state.solver.add(w >= 32)
state.solver.add(x >= 32)

state.solver.add(u <= 126)
state.solver.add(v <= 126)
state.solver.add(w <= 126)
state.solver.add(x <= 126)




aa = state.solver.BVS("aa",64)
bb = state.solver.BVS("bb",64)
cc = state.solver.BVS("cc",64)
dd = state.solver.BVS("dd",64)

state.solver.add(aa-bb == 46)
state.solver.add(cc-dd == 15)
state.solver.add(s^t^u == 51)
state.solver.add(aa+bb+cc+dd == 349)

state.solver.add(aa >= 32)
state.solver.add(bb >= 32)
state.solver.add(cc >= 32)
state.solver.add(dd >= 32)

state.solver.add(aa <= 126)
state.solver.add(bb <= 126)
state.solver.add(cc <= 126)
state.solver.add(dd <= 126)



ee = state.solver.BVS("ee",64)
ff = state.solver.BVS("ff",64)
gg = state.solver.BVS("gg",64)
hh = state.solver.BVS("hh",64)

state.solver.add(ee-ff == -49)
state.solver.add(gg-hh == -44)
state.solver.add(v^w^x == 101)
state.solver.add(ee+ff+gg+hh == 305)

state.solver.add(ee >= 32)
state.solver.add(ff >= 32)
state.solver.add(gg >= 32)
state.solver.add(hh >= 32)

state.solver.add(ee <= 126)
state.solver.add(ff <= 126)
state.solver.add(gg <= 126)
state.solver.add(hh <= 126)



ii = state.solver.BVS("ii",64)
jj = state.solver.BVS("jj",64)
kk = state.solver.BVS("kk",64)
ll = state.solver.BVS("ll",64)

state.solver.add(ii-jj == 47)
state.solver.add(kk-ll == 4)
state.solver.add(aa^bb^cc == 0)
state.solver.add(ii+jj+kk+ll == 257)

state.solver.add(ii >= 32)
state.solver.add(jj >= 32)
state.solver.add(kk >= 32)
state.solver.add(ll >= 32)

state.solver.add(ii <= 126)
state.solver.add(jj <= 126)
state.solver.add(kk <= 126)
state.solver.add(ll <= 126)


state.solver.add(dd^ee^ff == 0)
state.solver.add(gg^hh^ii == 15)
state.solver.add(jj^kk^ll == 48)





mm = state.solver.BVS("mm",64)
nn = state.solver.BVS("nn",64)
oo = state.solver.BVS("oo",64)
pp = state.solver.BVS("pp",64)

state.solver.add(mm-nn == 6)
state.solver.add(oo-pp == -7)
state.solver.add(mm^nn^oo == 116)
state.solver.add(mm+nn+oo+pp == 337)

state.solver.add(mm >= 32)
state.solver.add(nn >= 32)
state.solver.add(oo >= 32)
state.solver.add(pp >= 32)

state.solver.add(mm <= 126)
state.solver.add(nn <= 126)
state.solver.add(oo <= 126)
state.solver.add(pp <= 126)






qq = state.solver.BVS("qq",64)
rr = state.solver.BVS("rr",64)
ss = state.solver.BVS("ss",64)
tt = state.solver.BVS("tt",64)

state.solver.add(qq-rr == 47)
state.solver.add(ss-tt == 7)
state.solver.add(pp^qq^rr == 22)
state.solver.add(qq+rr+ss+tt == 340)

state.solver.add(qq >= 32)
state.solver.add(rr >= 32)
state.solver.add(ss >= 32)
state.solver.add(tt >= 32)

state.solver.add(qq <= 126)
state.solver.add(rr <= 126)
state.solver.add(ss <= 126)
state.solver.add(tt <= 126)





uu = state.solver.BVS("uu",64)
vv = state.solver.BVS("vv",64)
ww = state.solver.BVS("ww",64)
xx = state.solver.BVS("xx",64)

state.solver.add(uu-vv == -59)
state.solver.add(ww-xx == 52)
state.solver.add(ss^tt^uu == 10)
state.solver.add(uu+vv+ww+xx == 309)

state.solver.add(uu >= 32)
state.solver.add(vv >= 32)
state.solver.add(ww >= 32)
state.solver.add(xx >= 32)

state.solver.add(uu <= 126)
state.solver.add(vv <= 126)
state.solver.add(ww <= 126)
state.solver.add(xx <= 126)


state.solver.add(vv^ww^xx == 58)

aaa = state.solver.BVS("aaa",64)
bbb = state.solver.BVS("bbb",64)
ccc = state.solver.BVS("ccc",64)
ddd = state.solver.BVS("ddd",64)

state.solver.add(aaa-bbb == -15)
state.solver.add(ccc-ddd == 11)
state.solver.add(aaa^bbb^ccc == 125)
state.solver.add(aaa+bbb+ccc+ddd == 428)

state.solver.add(aaa >= 32)
state.solver.add(bbb >= 32)
state.solver.add(ccc >= 32)
state.solver.add(ddd >= 32)

state.solver.add(aaa <= 126)
state.solver.add(bbb <= 126)
state.solver.add(ccc <= 126)
state.solver.add(ddd <= 126)





eee = state.solver.BVS("eee",64)
fff = state.solver.BVS("fff",64)
ggg = state.solver.BVS("ggg",64)
hhh = state.solver.BVS("hhh",64)

state.solver.add(eee-fff == 7)
state.solver.add(ggg-hhh == 61)
state.solver.add(ddd^eee^fff == 100)
state.solver.add(eee+fff+ggg+hhh == 270)

state.solver.add(eee >= 32)
state.solver.add(fff >= 32)
state.solver.add(ggg >= 32)
state.solver.add(hhh >= 32)

state.solver.add(eee <= 126)
state.solver.add(fff <= 126)
state.solver.add(ggg <= 126)
state.solver.add(hhh <= 126)



iii = state.solver.BVS("iii",64)
jjj = state.solver.BVS("jjj",64)
kkk = state.solver.BVS("kkk",64)
lll = state.solver.BVS("lll",64)

#state.solver.add(iii-jjj == 7)
#state.solver.add(kkk-lll == 61)
state.solver.add(ggg^hhh^iii == 102)
state.solver.add(iii+jjj == 66)

state.solver.add(iii >= 32)
state.solver.add(jjj >= 32)
state.solver.add(kkk >= 32)
state.solver.add(lll >= 32)

state.solver.add(iii <= 126)
state.solver.add(jjj <= 126)
state.solver.add(kkk <= 126)
state.solver.add(lll <= 126)


z = []
z += [state.solver.eval(a),state.solver.eval(b),state.solver.eval(c),state.solver.eval(d)]
z += [state.solver.eval(e),state.solver.eval(f),state.solver.eval(g),state.solver.eval(h)]
z += [state.solver.eval(i),state.solver.eval(j),state.solver.eval(k),state.solver.eval(l)]
z += [state.solver.eval(m),state.solver.eval(n),state.solver.eval(o),state.solver.eval(p)]
z += [state.solver.eval(q),state.solver.eval(r),state.solver.eval(s),state.solver.eval(t)]
z += [state.solver.eval(u),state.solver.eval(v),state.solver.eval(w),state.solver.eval(x)]

z += [state.solver.eval(aa),state.solver.eval(bb),state.solver.eval(cc),state.solver.eval(dd)]
z += [state.solver.eval(ee),state.solver.eval(ff),state.solver.eval(gg),state.solver.eval(hh)]
z += [state.solver.eval(ii),state.solver.eval(jj),state.solver.eval(kk),state.solver.eval(ll)]
z += [state.solver.eval(mm),state.solver.eval(nn),state.solver.eval(oo),state.solver.eval(pp)]
z += [state.solver.eval(qq),state.solver.eval(rr),state.solver.eval(ss),state.solver.eval(tt)]
z += [state.solver.eval(uu),state.solver.eval(vv),state.solver.eval(ww),state.solver.eval(xx)]

z += [state.solver.eval(aaa),state.solver.eval(bbb),state.solver.eval(ccc),state.solver.eval(ddd)]
z += [state.solver.eval(eee),state.solver.eval(fff),state.solver.eval(ggg),state.solver.eval(hhh)]
z += [state.solver.eval(iii),state.solver.eval(jjj)]

for i in z:
    print(chr(i),end="")
print()

'''
_a = [-43, 61, 58, 5, -4, -11, 64, -40, -43, 61, 62, -51, 46, 15, -49, -44, 47, 4, 6, -7, 47, 7, -59, 52, -15, 11, 7, 61]
_b = [6, 106, 10, 0, 119, 52, 51, 101, 0, 0, 15, 48, 116, 22, 10, 58, 125, 100, 102, 33]
_c = [304, 357, 303, 320, 304, 307, 349, 305, 257, 337, 340, 309, 428, 270, 66]
'''


#[51, 94, 107, 52]
#[108, 50, 52, 94]
#[60, 64, 118, 61]
#[100, 36, 64, 120]
