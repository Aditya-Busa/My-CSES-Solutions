// Author : Aditya Busa

#include <iostream>
#include <string>
#include<vector>
#include<algorithm>
using namespace std;
#define ll long long int
#define mod 1000000007
#define fu(i, a, b) for (ll i(a); i < b; i++)
#define fd(i, a, b) for (ll i(a); i > b; i--)

int main()
{
    ios_base::sync_with_stdio(0);
    cin.tie(0);
    string s;
    cin >> s;
    vector<ll> count(26, 0);
    fu(i, 0, s.length())
    {
        count[s[i] - 65]++;
    }
    if (s.length() % 2 == 0)
    {
        bool flag = true;
        fu(i, 0, 26)
        {
            if (count[i] % 2 != 0)
            {
                flag = false;
                break;
            }
            else
            {
                count[i] /= 2;
            }
        }
        if (flag)
        {
            string ans;
            fu(i, 0, 26)
            {
                fu(j, 0, count[i])
                {
                    ans += ('A' + i);
                }
            }
            string temp = ans;
            reverse(ans.begin(), ans.end());
            temp += ans;
            cout << temp;
        }
        else
        {
            cout << "NO SOLUTION";
        }
    }
    else
    {
        ll no_of_odd = 0;
        ll the_odd;
        fu(i, 0, 26)
        {
            if (count[i] % 2 != 0)
            {
                the_odd = i;
                no_of_odd++;
                count[i] = (count[i]-1)/2;
            }
            else
            {
                count[i] /= 2;
            }
        }
        if(no_of_odd == 1)
        {
                        string ans;
            fu(i, 0, 26)
            {
                fu(j, 0, count[i])
                {
                    ans += ('A' + i);
                }
            }
            string temp = ans;
            reverse(ans.begin(), ans.end());
            temp+= ('A'+the_odd);
            temp += ans;
            cout << temp;
        }
        else
        {
            cout<<"NO SOLUTION";
        }
    }
}
