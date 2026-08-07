import { useState } from "react";
import {
    Navigate,
    Link,
    useNavigate,
} from "react-router-dom";

import {
    ShieldCheck,
    ArrowRight,
    User,
    Eye,
    EyeOff,
} from "lucide-react";



import { useAuth } from "../context/AuthContext";

export default function Login() {

    const {
        login,
        isAuthenticated,
    } = useAuth();

    const navigate = useNavigate();

    const [username, setUsername] =
        useState("");

    const [password, setPassword] =
        useState("");

    const [rememberDevice, setRememberDevice] =
        useState(true);

    const [showPassword, setShowPassword] =
        useState(false);

    const [loading, setLoading] =
        useState(false);

    const [error, setError] =
        useState("");

    if (isAuthenticated) {

        return (
            <Navigate
                to="/dashboard"
                replace
            />
        );

    }

    async function handleSubmit(e) {

        e.preventDefault();

        setError("");
        setLoading(true);

        try {

            await login(
                username,
                password
            );
            navigate(
                "/dashboard",
                {
                    replace: true,
                }
            );

        }
        catch (err) {

            setError(

                err.response?.data?.detail ??

                "Unable to sign in."

            );

        }
        finally {

            setLoading(false);

        }

    }

    return (

        <div className="auth-page auth-page-login">

            {/* ======================================================
                LOGIN PANEL
            ====================================================== */}

            <section className="auth-panel auth-panel-full">

                <div className="auth-card">

                    <div className="auth-logo">

                        <div className="auth-logo-mark">

                            <ShieldCheck size={28} />

                        </div>

                        <div className="auth-logo-text">

                            <h1>

                                SecureSense AI

                            </h1>

                            <p>

                                Security Investigation Workspace

                            </p>

                        </div>

                    </div>

                    <div className="auth-heading">

                        <h2>

                            Welcome Back

                        </h2>

                        <p>

                            Sign in to continue your
                            security investigations.

                        </p>

                    </div>

                    {

                        error && (

                            <div
                                className="auth-alert auth-alert-error"
                            >

                                {error}

                            </div>

                        )

                    }

                    <form
                        onSubmit={handleSubmit}
                        className="auth-form"
                    >

                        <div
                            className="auth-field"
                        >

                            <label
                                className="auth-label"
                            >

                                Username

                            </label>

                            <div
                                className="auth-input-wrapper"
                            >

                                <input
                                    className="auth-input"
                                    value={username}
                                    onChange={(e)=>
                                        setUsername(
                                            e.target.value
                                        )
                                    }
                                    placeholder="Enter username"
                                    required
                                />

                                <User
                                    size={18}
                                    style={{
                                        position:"absolute",
                                        right:18,
                                        top:"50%",
                                        transform:"translateY(-50%)",
                                        color:"#64748b",
                                    }}
                                />

                            </div>

                        </div>

                        <div
                            className="auth-field"
                        >

                            <label
                                className="auth-label"
                            >

                                Password

                            </label>

                            <div
                                className="auth-password"
                            >

                                <input
                                    className="auth-input"
                                    type={
                                        showPassword
                                            ? "text"
                                            : "password"
                                    }
                                    value={password}
                                    onChange={(e)=>
                                        setPassword(
                                            e.target.value
                                        )
                                    }
                                    placeholder="Enter password"
                                    required
                                />

                                <button
                                    type="button"
                                    className="auth-password-toggle"
                                    onClick={()=>
                                        setShowPassword(
                                            !showPassword
                                        )
                                    }
                                >

                                    {

                                        showPassword

                                            ?

                                            <EyeOff
                                                size={18}
                                            />

                                            :

                                            <Eye
                                                size={18}
                                            />

                                    }

                                </button>

                            </div>

                        </div>
                                                <div
                            className="auth-options"
                        >

                            <label
                                className="auth-checkbox"
                            >

                                <input
                                    type="checkbox"
                                    checked={rememberDevice}
                                    onChange={() =>
                                        setRememberDevice(
                                            !rememberDevice
                                        )
                                    }
                                />

                                Remember this device

                            </label>

                            <Link
                                to="#"
                                className="auth-link"
                                onClick={(e) =>
                                    e.preventDefault()
                                }
                            >

                                Forgot password?

                            </Link>

                        </div>

                        <button
                            type="submit"
                            className="auth-button"
                            disabled={loading}
                        >

                            {

                                loading

                                    ?

                                    <>

                                        <span
                                            className="auth-spinner"
                                        />

                                        Signing In...

                                    </>

                                    :

                                    <>

                                        Sign In

                                        <ArrowRight
                                            size={18}
                                        />

                                    </>

                            }

                        </button>

                    </form>

                    <div
                        className="auth-footer"
                    >

                        Don't have an account?

                        {" "}

                        <Link
                            to="/register"
                        >

                            Create Account

                        </Link>

                    </div>

                    <div
                        className="auth-platform-note"
                    >

                        SecureSense AI is an enterprise
                        security investigation platform for
                        analyzing digital communications
                        through multimodal intelligence,
                        explainable evidence, trust
                        relationships and authenticity
                        verification.

                    </div>

                </div>

            </section>

        </div>

    );

}