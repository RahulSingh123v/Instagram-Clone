export function getCSRFToken(): string{
    const cookies = document.cookie.split(";");

    for (const token of cookies){

        const cookie = token.trim()

        if (cookie.startsWith("csrftoken=")){
            return cookie.substring("csrftoken=".length)
        
        }

    } 
    return ""
}