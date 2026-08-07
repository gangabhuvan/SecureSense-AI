import {
    createContext,
    useContext,
    useEffect,
    useState,
} from "react";

import {
    getCurrentUser,
    loginUser,
    logoutUser,
    registerUser,
} from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {

    const [user, setUser] = useState(null);

    const [loading, setLoading] = useState(true);

    useEffect(() => {

        const initialize = async () => {

            const token =
                localStorage.getItem(
                    "access_token"
                );

            if (!token) {
                setLoading(false);
                return;
            }

            try {

                const currentUser =
                    await getCurrentUser();

                setUser(currentUser);

            } catch {

                localStorage.removeItem(
                    "access_token"
                );

                setUser(null);

            } finally {

                setLoading(false);

            }
        };

        initialize();

    }, []);

    const login = async (
        username,
        password
    ) => {

        await loginUser({
            username,
            password,
        });

        const currentUser =
            await getCurrentUser();

        setUser(currentUser);
    };

    const register = async (
        username,
        email,
        password
    ) => {

        await registerUser({
            username,
            email,
            password,
        });
    };

    const logout = async () => {

        await logoutUser();

        setUser(null);
    };

    return (

        <AuthContext.Provider
            value={{
                user,
                loading,
                login,
                logout,
                register,
                isAuthenticated:
                    !!user,
            }}
        >
            {children}
        </AuthContext.Provider>

    );
}

export function useAuth() {

    return useContext(
        AuthContext
    );
}