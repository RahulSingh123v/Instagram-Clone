

let isRefreshing = false;
let refreshPromise: Promise<void> | null = null;

async function refreshToken(){
    if (isRefreshing && refreshPromise){
        return refreshPromise
    }

    isRefreshing = true;

    refreshPromise = fetch("http://localhost:8000/api/auth/refresh",{
        method: "POST",
        credentials:"include"
    })
    .then(async (res) => {
        if (!res.ok){
            throw new Error("Refresh Failed")
        }
    })
    .finally(() => {
        isRefreshing = false;
        refreshPromise = null;
    });
    return refreshPromise;
}


export async function apiFetch(
    url: string,
    options: RequestInit = {}
){
    const response = await fetch(url,{
        ...options,
        credentials: "include",
        headers: {
            "Content-Type": "application/json",
            ...(options.headers || {}),
        }

    });

    if (response.status === 401){
        try {
            await refreshToken();

            return fetch(url,{
                ...options,
                credentials: "include",
            });
        }
        catch{
            window.location.href = "/login";
            throw new Error("Authentication refresh failed");
        }
    }
    return response;

}