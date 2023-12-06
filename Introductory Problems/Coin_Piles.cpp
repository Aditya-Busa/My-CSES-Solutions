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
    ll t;
    cin >> t;
    while (t--)
    {
        ll a, b;
        cin >> a >> b;
        ll min = a;
        ll max = b;
        if (a > b)
        {
            min = b;
            max = a;
        }
        if (max > 2 * min)
            cout << "NO\n";
        else
        {
            min = 2 * min - max;
            if (min % 3 == 0)
                cout << "YES\n";
            else
                cout << "NO\n";
        }
    }
}
