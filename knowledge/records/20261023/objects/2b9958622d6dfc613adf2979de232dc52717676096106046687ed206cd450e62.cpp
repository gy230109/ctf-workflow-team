#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <numeric>
#include <random>
#include <string>
#include <vector>
using namespace std;
int main(int argc, char** argv) {
 if(argc<3) return 2;
 const int N=26*26*26*26;
 vector<double> grams(N,-12.0); vector<pair<int,double>> vals; double total=0;
 ifstream gf(argv[1]); string s; double n;
 while(gf>>s>>n) { int q=0; for(char c:s) q=q*26+c-'A'; if(s.size()==4) {vals.push_back({q,n});total+=n;}}
 double floor=log(0.1/total); fill(grams.begin(),grams.end(),floor);
 for(auto v:vals)grams[v.first]=log(v.second/total);
 ifstream cf(argv[2]); string cipher; while(getline(cf,s))cipher+=s;
 string alphabet; vector<int> enc; for(char c:cipher) {
   auto pos=alphabet.find(c); if(pos==string::npos){pos=alphabet.size();alphabet+=c;}
   enc.push_back(pos);
 }
 if(alphabet.size()>26)return 3;
 array<int,26> key; iota(key.begin(),key.end(),0); mt19937 rng(43);
 auto score=[&](const array<int,26>& k){double sc=0; for(int j=0;j+3<(int)enc.size();j++){
    int idx=((k[enc[j]]*26+k[enc[j+1]])*26+k[enc[j+2]])*26+k[enc[j+3]];
    sc+=grams[idx];}return sc;};
 double best=-1e9; auto begin=chrono::steady_clock::now();
 for(int restart=0;restart<1200;restart++){
  shuffle(key.begin(),key.end(),rng);double sc=score(key);
  for(int step=0;step<10000;step++){
   int a=rng()%26,b=rng()%26;if(a==b)continue;
   swap(key[a],key[b]);double ns=score(key);double temp=5.0*(1.0-double(step)/10000)+0.1;
   if(ns>=sc || log((rng()+1.0)/(rng.max()+2.0))<(ns-sc)/temp)sc=ns; else swap(key[a],key[b]);
   if(sc>best){best=sc;cout<<"best "<<best<<" restart "<<restart<<"\n";
    for(int v:enc)cout<<char('A'+key[v]);cout<<"\n";
    for(int i=0;i<(int)alphabet.size();i++)cout<<alphabet[i]<<":"<<char('A'+key[i])<<" ";cout<<"\n";cout.flush();}
  }
  if(chrono::duration<double>(chrono::steady_clock::now()-begin).count()>40)break;
 }
}
