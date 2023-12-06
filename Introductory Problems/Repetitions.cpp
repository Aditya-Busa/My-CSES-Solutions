// Author : Aditya Busa

#include <iostream>
#include <string>
using namespace std;
#define ll long long int
#define mod 1000000007
#define fu(i, a, b) for (ll i(a); i < b; i++)
#define fd(i, a, b) for (ll i(a); i > b; i--)

int main()
{
    ios_base::sync_with_stdio(0);
    cin.tie(0);
    string giv;
    cin >> giv;
    char now = giv[0];
    ll ans = 1;
    ll temp = 1;
    fu(i,1,giv.length())
    {
        if(giv[i] == now)
        {
            temp++;
        }
        else
        {
            if(ans < temp) ans = temp;
            temp = 1;
            now = giv[i];
        }
    }
    if(ans<temp) ans = temp; //// I missed this line while coding for the first time, think of the cases that missed due to this
    cout<<ans;
}
