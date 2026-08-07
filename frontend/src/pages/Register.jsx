import { useState } from "react";

import {
    Link,
    Navigate,
    useNavigate,
} from "react-router-dom";

import {
    ShieldCheck,
    ArrowRight,
    User,
    Mail,
    Eye,
    EyeOff,
} from "lucide-react";

import { useAuth } from "../context/AuthContext";

export default function Register() {

    const {
        register,
        isAuthenticated,
    } = useAuth();

    const navigate =
        useNavigate();

    const [username, setUsername] =
        useState("");

    const [email, setEmail] =
        useState("");

    const [password, setPassword] =
        useState("");

    const [
        confirmPassword,
        setConfirmPassword,
    ] = useState("");

    const [
        showPassword,
        setShowPassword,
    ] = useState(false);

    const [
        showConfirmPassword,
        setShowConfirmPassword,
    ] = useState(false);

    const [
        loading,
        setLoading,
    ] = useState(false);

    const [
        error,
        setError,
    ] = useState("");

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

        if (
            password !==
            confirmPassword
        ) {

            setError(
                "Passwords do not match."
            );

            return;

        }

        setLoading(true);

        try {

            await register(
                username,
                email,
                password,
            );

            navigate(
    "/login",
    {
        replace: true,
    }
);

        }
        catch (err) {

            setError(

                err.response?.data?.detail ??

                "Unable to create account."

            );

        }
        finally {

            setLoading(false);

        }

    }

    return (

        <div className="auth-page auth-page-login">

            {/* ======================================================
                REGISTER PANEL
            ====================================================== */}

            <section className="auth-panel auth-panel-full">

                <div className="auth-card">

                    <div className="auth-logo">

                        <div className="auth-logo-mark">

                            <ShieldCheck
                                size={28}
                            />

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

    Create Your Account

</h2>

<p>

    Join SecureSense AI and access the
    investigation workspace.

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
                    >                        <div
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
                                    placeholder="Choose a username"
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

                                Email Address

                            </label>

                            <div
                                className="auth-input-wrapper"
                            >

                                <input
                                    className="auth-input"
                                    type="email"
                                    value={email}
                                    onChange={(e)=>
                                        setEmail(
                                            e.target.value
                                        )
                                    }
                                    placeholder="Enter your email"
                                    required
                                />

                                <Mail
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
                                    placeholder="Create a password"
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
                            className="auth-field"
                        >

                            <label
                                className="auth-label"
                            >

                                Confirm Password

                            </label>

                            <div
                                className="auth-password"
                            >

                                <input
                                    className="auth-input"
                                    type={
                                        showConfirmPassword
                                            ? "text"
                                            : "password"
                                    }
                                    value={confirmPassword}
                                    onChange={(e)=>
                                        setConfirmPassword(
                                            e.target.value
                                        )
                                    }
                                    placeholder="Confirm your password"
                                    required
                                />

                                <button
                                    type="button"
                                    className="auth-password-toggle"
                                    onClick={()=>
                                        setShowConfirmPassword(
                                            !showConfirmPassword
                                        )
                                    }
                                >

                                    {

                                        showConfirmPassword

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

                                        Creating Account...

                                    </>

                                    :

                                    <>

                                        Create Account

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

                        Already have an account?

                        {" "}

                        <Link
                            to="/login"
                        >

                            Sign In

                        </Link>

                    </div>

                    <div
                        className="auth-platform-note"
                    >

                        Your account provides access to
the SecureSense AI investigation
workspace for secure communication
analysis, explainable evidence and
trust-based investigation workflows.

                    </div>

                </div>

            </section>

        </div>

    );

}