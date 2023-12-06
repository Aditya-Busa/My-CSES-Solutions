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
    if(n==1)cout<<1;
    else if(n<4) cout<<"NO SOLUTION";
    else
    {
        for(int i =2;i<=n;i+=2)
        {
            cout<<i<<" ";
        }
        for(int i =1;i<=n;i+=2)
        {
            cout<<i<<" ";
        }
    }
}
