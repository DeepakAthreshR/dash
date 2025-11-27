import { createContext, useEffect, useReducer } from "react";
import axios from "axios";

const initialState = { notifications: [] };

const reducer = (state, action) => {
  switch (action.type) {
    case "LOAD_NOTIFICATIONS": {
      return { ...state, notifications: Array.isArray(action.payload) ? action.payload : [] };
    }
    case "DELETE_NOTIFICATION": {
      return { ...state, notifications: Array.isArray(action.payload) ? action.payload : [] };
    }
    case "CLEAR_NOTIFICATIONS": {
      return { ...state, notifications: Array.isArray(action.payload) ? action.payload : [] };
    }
    default:
      return state;
  }
};

const NotificationContext = createContext({
  notifications: [],
  deleteNotification: () => {},
  clearNotifications: () => {},
  getNotifications: () => {},
  createNotification: () => {}
});

export const NotificationProvider = ({ children }) => {
  const [state, dispatch] = useReducer(reducer, initialState);

  const deleteNotification = async (notificationID) => {
    try {
      // No backend, just clear notifications
      dispatch({ type: "DELETE_NOTIFICATION", payload: [] });
    } catch (e) {
      console.error(e);
    }
  };

  const clearNotifications = async () => {
    try {
      dispatch({ type: "CLEAR_NOTIFICATIONS", payload: [] });
    } catch (e) {
      console.error(e);
    }
  };

  const getNotifications = async () => {
    try {
      dispatch({ type: "LOAD_NOTIFICATIONS", payload: [] });
    } catch (e) {
      console.error(e);
    }
  };

  const createNotification = async (notification) => {
    try {
      // No backend, just ignore
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    getNotifications();
  }, []);

  return (
    <NotificationContext.Provider
      value={{
        getNotifications,
        deleteNotification,
        clearNotifications,
        createNotification,
        notifications: state.notifications
      }}>
      {children}
    </NotificationContext.Provider>
  );
};

export default NotificationContext;
