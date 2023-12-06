// Author : Aditya Busa

#include <iostream>
using namespace std;
#define ll long long int
#define mod 1000000007
#define fu(i, a, b) for (ll i(a); i < b; i++)
#define fd(i, a, b) for (ll i(a); i > b; i--)

int main()
{
    ios_base::sync_with_stdio(0);
    cin.tie(0);
    ll n;
    cin >> n;
    ll ans = 0;
    while(n != 0){
        n/=5;
        ans+=n;
    }
    cout<<ans;
}
