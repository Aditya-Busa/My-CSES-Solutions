// Aditya Busa

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
    while(n!=1){
        cout<<n<<" ";
        if(n%2 == 0)
        {
            n/=2;
        }
        else
        {
            n = 3*n + 1;
        }
    }
    cout<<1;
    
}
