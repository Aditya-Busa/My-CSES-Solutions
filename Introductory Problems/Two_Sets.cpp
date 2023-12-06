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
    ll sum = (n * (n + 1)) / 2;
    if (sum % 2 != 0)
        cout << "NO";
    else
    {
        cout << "YES\n";
        if (n % 2 == 0)
        {
            cout << n / 2 << '\n';
            fu(i, 1, n / 4 + 1)
            {
                cout << i << " " << n + 1 - i << " ";
            }
            cout << '\n'
                 << n / 2 << '\n';
            fu(i, n / 4 + 1, n / 2 + 1)
            {
                cout << i << " " << n + 1 - i << " ";
            }
        }
        else
        {
            cout << n / 2 << '\n';
            cout << n << " ";
            ll start = (n - 1) / 2;
            ll end = (start - 1) / 2;
            ll i = 1;
            while (i != end + 1)
            {
                cout << i << " " << n - i << " ";
                i++;
            }
            cout << '\n';
            cout << n / 2 + 1 << '\n';
            while (i != start + 1)
            {
                cout << i << " " << n - i << " ";
                i++;
            }
        }
    }
}
