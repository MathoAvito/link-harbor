// src/components/AnalyticsDashboard.jsx
import React from 'react';
import { useLinks } from '../context/LinkContext';

const AnalyticsDashboard = () => {
    const { links } = useLinks();

    // Calculate overall statistics
    const totalLinks = links.length;
    const totalClicks = links.reduce((sum, link) => sum + (link.clicks || 0), 0);
    const averageClicks = totalLinks ? (totalClicks / totalLinks).toFixed(1) : 0;
    const totalCategories = [...new Set(links.map(link => link.category).filter(Boolean))].length;

    // Find most clicked link
    const mostClickedLink = links.length ?
        [...links].sort((a, b) => (b.clicks || 0) - (a.clicks || 0))[0] :
        null;

    // Calculate category distribution
    const categoryData = links.reduce((acc, link) => {
        const category = link.category || 'Uncategorized';
        acc[category] = (acc[category] || 0) + 1;
        return acc;
    }, {});

    return (
        <div className="bg-white rounded-lg shadow-lg p-6">
            <h2 className="text-2xl font-bold text-gray-800 mb-6">Analytics Dashboard</h2>

            {/* Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
                <div className="bg-blue-50 rounded-lg p-4">
                    <p className="text-blue-600 text-sm font-medium">Total Links</p>
                    <p className="text-3xl font-bold">{totalLinks}</p>
                </div>

                <div className="bg-green-50 rounded-lg p-4">
                    <p className="text-green-600 text-sm font-medium">Total Clicks</p>
                    <p className="text-3xl font-bold">{totalClicks}</p>
                </div>

                <div className="bg-purple-50 rounded-lg p-4">
                    <p className="text-purple-600 text-sm font-medium">Average Clicks</p>
                    <p className="text-3xl font-bold">{averageClicks}</p>
                </div>

                <div className="bg-yellow-50 rounded-lg p-4">
                    <p className="text-yellow-600 text-sm font-medium">Categories</p>
                    <p className="text-3xl font-bold">{totalCategories}</p>
                </div>
            </div>

            {/* Most Clicked Link */}
            {mostClickedLink && (
                <div className="mb-8">
                    <h3 className="text-lg font-semibold text-gray-700 mb-3">Most Clicked Link</h3>
                    <div className="bg-gray-50 rounded-lg p-4">
                        <div className="flex items-center">
                            <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center mr-3">
                                <span className="text-white font-bold">{mostClickedLink.name.charAt(0).toUpperCase()}</span>
                            </div>
                            <div>
                                <h4 className="font-medium">{mostClickedLink.name}</h4>
                                <p className="text-sm text-gray-500">{mostClickedLink.url}</p>
                            </div>
                            <div className="ml-auto">
                                <span className="bg-blue-100 text-blue-800 text-sm font-medium px-2.5 py-0.5 rounded">
                                    {mostClickedLink.clicks || 0} clicks
                                </span>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Category Distribution */}
            <div>
                <h3 className="text-lg font-semibold text-gray-700 mb-3">Category Distribution</h3>
                <div className="bg-gray-50 rounded-lg p-4">
                    {Object.entries(categoryData).length > 0 ? (
                        <div className="space-y-3">
                            {Object.entries(categoryData)
                                .sort((a, b) => b[1] - a[1])
                                .map(([category, count]) => (
                                    <div key={category} className="flex items-center">
                                        <span className="text-sm font-medium w-32 truncate">{category}</span>
                                        <div className="flex-grow ml-2">
                                            <div className="w-full bg-gray-200 rounded-full h-2.5">
                                                <div
                                                    className="bg-blue-600 h-2.5 rounded-full"
                                                    style={{ width: `${(count / totalLinks) * 100}%` }}
                                                ></div>
                                            </div>
                                        </div>
                                        <span className="ml-2 text-sm text-gray-500">{count}</span>
                                    </div>
                                ))}
                        </div>
                    ) : (
                        <p className="text-gray-500 text-center py-4">No data available</p>
                    )}
                </div>
            </div>
        </div>
    );
};

export default AnalyticsDashboard;