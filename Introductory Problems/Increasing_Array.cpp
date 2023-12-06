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
    ll prev,now;
    ll ans = 0;

    cin>>prev;
    
    fu(i, 0, n-1)
    {
        cin>>now;
        if(now > prev) prev = now;
        else ans+=(prev - now);
    }
  
    cout<<ans;
}
