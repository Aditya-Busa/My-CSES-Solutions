// Author : Aditya Busa

#include <iostream>
using namespace std;
#define ll long long int
#define mod 1000000007
#define fu(i, a, b) for (ll i(a); i < b; i++)
#define fd(i, a, b) for (ll i(a); i > b; i--)

ll ans(ll y, ll x)
{
    ll a = y;
    if (x > y)
        a = x;

    if (a % 2 == 0)
    {
        if (y == a)
        {
            return a * a - (x - 1);
        }
        else
        {
            return a * a - (a - 1) - (a - y);
        }
    }
    else
    {
        if (y == a)
        {
            return a * a - (a - 1) - (a - x);
        }
        else
        {
            return a * a - (y - 1);
        }
    }
}
int main()
{
    ios_base::sync_with_stdio(0);
    cin.tie(0);
    ll t;
    cin >> t;
    while (t--)
    {
        ll y, x;
        cin >> y >> x;
        cout << ans(y, x) << '\n';
    }
}
