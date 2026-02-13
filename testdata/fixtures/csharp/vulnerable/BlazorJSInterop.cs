using System.Threading.Tasks;
using Microsoft.JSInterop;

namespace VulnerableApp.Components
{
    public class DangerousComponent
    {
        private readonly IJSRuntime _jsRuntime;

        public DangerousComponent(IJSRuntime jsRuntime)
        {
            _jsRuntime = jsRuntime;
        }

        // Vulnerable: eval with user-controlled code
        public async Task ExecuteCode(string userCode)
        {
            await _jsRuntime.InvokeAsync<string>("eval", userCode);
        }

        // Vulnerable: string interpolation in function name
        public async Task CallDynamic(string funcName)
        {
            await _jsRuntime.InvokeVoidAsync($"window.{funcName}");
        }
    }
}
