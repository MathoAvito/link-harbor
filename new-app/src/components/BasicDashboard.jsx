// src/components/BasicDashboard.jsx
import React from 'react';
import { useUser } from '../context/UserContext';

const BasicDashboard = () => {
    const { user, logout } = useUser();

    return (
        <div className="flex h-screen">
            {/* Sidebar - ONLY this should appear on the left */}
            <div className="w-64 bg-blue-900 text-white">
                <div className="p-4">
                    <h1 className="text-xl font-bold">Link Harbor</h1>
                    <p className="text-sm opacity-75">Your personal link dashboard</p>
                </div>

                <div className="p-4">
                    <button className="w-full bg-blue-700 hover:bg-blue-600 text-white px-4 py-2 rounded">
                        + Add New Link
                    </button>
                </div>

                <div className="p-4">
                    <h2 className="uppercase text-xs font-bold opacity-75 mb-2">Browse</h2>
                    <div className="space-y-1">
                        <button className="flex justify-between items-center w-full p-2 rounded bg-blue-800">
                            <span>All Links</span>
                            <span className="bg-blue-700 px-2 py-0.5 rounded-full text-xs">0</span>
                        </button>

                        <button className="flex justify-between items-center w-full p-2 rounded hover:bg-blue-800">
                            <span>Favorites</span>
                            <span className="bg-blue-700 px-2 py-0.5 rounded-full text-xs">0</span>
                        </button>
                    </div>
                </div>

                <div className="mt-auto p-4 border-t border-blue-800">
                    <button
                        onClick={logout}
                        className="text-sm opacity-75 hover:opacity-100"
                    >
                        Logout
                    </button>
                </div>
            </div>

            {/* Main content - this is the main area */}
            <div className="flex-1 bg-gray-100">
                <header className="bg-white border-b p-4">
                    <h1 className="text-xl font-bold">All Links</h1>
                </header>

                <main className="p-6">
                    <div className="bg-white p-8 rounded shadow-sm text-center">
                        <h2 className="text-xl font-medium mb-2">You haven't added any links yet</h2>
                        <p className="text-gray-500 mb-6">Start building your collection by adding your first link.</p>
                        <button className="bg-blue-600 text-white px-4 py-2 rounded">
                            + Add Your First Link
                        </button>
                    </div>
                </main>
            </div>
        </div>
    );
};

export default BasicDashboard;