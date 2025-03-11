import { useEffect, useRef } from 'react';

/**
 * Hook that alerts when you click outside of the passed ref
 * @param {Function} callback - Function to call on outside click
 * @returns {React.RefObject} - Ref to attach to element
 */
export const useOutsideClick = (callback) => {
    const ref = useRef();

    useEffect(() => {
        const handleClick = (event) => {
            if (ref.current && !ref.current.contains(event.target)) {
                callback();
            }
        };

        document.addEventListener('mousedown', handleClick);

        return () => {
            document.removeEventListener('mousedown', handleClick);
        };
    }, [callback]);

    return ref;
};