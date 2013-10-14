#include <iostream>
#include <string>
#include <memory>
#include <Windows.h>
#include "openvpn-plugin.h"

using namespace std;

const TCHAR MsgHeader[] = "[auth_windows] ";

template <typename Ptr>
struct local_release
{
	typedef Ptr pointer;

	void operator()(Ptr ptr) const { LocalFree(ptr); }
};

struct Context
{
	unique_ptr<PSID, local_release<PSID>> groupSid;
};

unique_ptr<const string> env_get(const char *envp[], const string& key)
{
	const auto keylen = key.length();

	for(int i = 0; envp[i]; ++i)
	{
		const auto& entry = string(envp[i]);

		if(!entry.compare(0, keylen, key) && entry.at(keylen) == '=')
		{
			return unique_ptr<const string>(new string(entry.substr(keylen + 1)));
		}
	}

	return nullptr;
}

OPENVPN_EXPORT openvpn_plugin_handle_t
openvpn_plugin_open_v1 (unsigned int *type_mask, const char *argv[], const char *envp[])
{
	auto ctx = new Context();
	
	*type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);

	const auto accept_account = env_get(envp, "auth_windows_group");
	if(accept_account)
	{
		DWORD cbSid = 0;
		TCHAR szDomainName[256];
		DWORD dwSizeDomain = sizeof(szDomainName) / sizeof(TCHAR);
		SID_NAME_USE sidUsage;
		
		LookupAccountName(NULL, accept_account->c_str(), NULL, &cbSid, szDomainName, &dwSizeDomain, &sidUsage);
		ctx->groupSid.reset(LocalAlloc(LPTR, cbSid));
		if(!LookupAccountName(NULL, accept_account->c_str(), ctx->groupSid.get(), &cbSid, szDomainName, &dwSizeDomain, &sidUsage))
		{
			delete ctx;
			cout << MsgHeader << "LookupAccountName fails with error " << GetLastError() << "." << endl;
			cout << MsgHeader << "Error: Account '" << *accept_account << "' was not found." << endl;
			return nullptr;
		}
		switch(sidUsage){
		case SidTypeAlias: // for builtin groups
		case SidTypeGroup:
		case SidTypeWellKnownGroup:
			cout << MsgHeader << "Accepts only member of '" << *accept_account << "'." << endl;
			break;
		case SidTypeUser:
			cout << MsgHeader << "Accepts only '" << *accept_account << "'." << endl;
			break;
		default:
			delete ctx;
			cout << MsgHeader << "Error: Account '" << *accept_account << "'(" << sidUsage << ") is not user or group. " << endl;
			return nullptr;
		}
	}else{
		cout << MsgHeader << "Accepts all users." << endl;
	}

	return static_cast<openvpn_plugin_handle_t>(ctx);
}

OPENVPN_EXPORT int
openvpn_plugin_func_v1 (openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[])
{
	return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT void
openvpn_plugin_close_v1 (openvpn_plugin_handle_t handle)
{
	delete static_cast<Context *>(handle);
}