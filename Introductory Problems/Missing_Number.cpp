// Author : Aditya Busa

#include<iostream>
using namespace std;
#define ll long long int
#define mod 1000000007
#define fu(i,a,b) for(ll i(a);i<b;i++)
#define fd(i,a,b) for(ll i(a);i>b;i--)

int main(){
    ios_base::sync_with_stdio(0);
    cin.tie(0);
    ll n;
    cin>>n;
  
    // Given n < 2.10^5 so n(n+1) is within long long int
    // The idea used below is self explanatory so skipping the explanation
    ll sum = (n*(n+1))/2;
    ll a;
    fu(i,0,n-1){
        cin>>a;
        sum-=a;
    }
    cout<<sum;
}
