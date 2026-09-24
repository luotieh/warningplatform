import { io, type Socket } from "socket.io-client";

type Listener = (data?: any) => void;
type SocketEvent = "connected" | "disconnected" | "error" | "new_message" | "chat_delta" | "event_list_update";
type SocketStatus = "connected" | "connecting" | "disconnected";

const MESSAGE_EVENTS = [
  "new_message",
  "message",
  "chat_message",
  "event_message",
  "engineer_chat",
] as const;

class DeepflowSocketManager {
  private joinedRooms = new Set<string>();
  private listeners = new Map<SocketEvent, Listener[]>();
  public status: SocketStatus = "disconnected";
  public socket: null | Socket = null;

  get connected() {
    return Boolean(this.socket?.connected);
  }

  connect() {
    if (this.socket) {
      if (this.socket.connected || !this.socket.disconnected) return;
      this.socket.disconnect();
      this.socket = null;
    }

    if (typeof window === "undefined") return;

    const token = localStorage.getItem("deepflow_token") || "";
    this.status = "connecting";
    // console.info('[DeepFlow Socket] connecting:', {
    //   origin: window.location.origin,
    //   path: '/api/socket.io',
    //   token: Boolean(token),
    //   transports: ['websocket'],
    // });
    this.socket = io(window.location.origin, {
      auth: token ? { token } : undefined,
      autoConnect: false,
      forceNew: true,
      multiplex: false,
      path: "/api/traffic/socket.io",
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      transports: ["websocket"],
    });

    this.socket.on("connect", () => {
      this.status = "connected";
      // console.info('[DeepFlow Socket] connected:', {
      //   id: this.socket?.id,
      //   transport: this.socket?.io.engine?.transport?.name,
      // });
      this.emit("connected");
      this.rejoinRooms();
    });

    this.socket.io.on("open", () => {
      // console.info('[DeepFlow Socket] engine open:', {
      //   transport: this.socket?.io.engine?.transport?.name,
      // });
      this.socket?.io.engine?.on("packet", () => {
        // console.info('[DeepFlow Socket] engine packet:', packet);
      });
      this.socket?.io.engine?.on("packetCreate", () => {
        // console.info('[DeepFlow Socket] engine packetCreate:', packet);
      });
    });

    this.socket.io.on("close", () => {
      // console.warn('[DeepFlow Socket] engine close:', reason);
    });

    this.socket.io.on("error", () => {
      // console.error('[DeepFlow Socket] engine error:', error);
    });

    this.socket.on("disconnect", () => {
      this.status = "disconnected";
      this.emit("disconnected");
    });

    this.socket.on("connect_error", (error) => {
      this.status = "disconnected";
      // console.error('[DeepFlow Socket] connect_error:', error);
      this.emit("error", error);
    });

    this.socket.on("error", (error) => {
      this.status = "disconnected";
      // console.error('[DeepFlow Socket] error:', error);
      this.emit("error", error);
    });

    MESSAGE_EVENTS.forEach((event) => {
      this.socket?.on(event, (data) => {
        this.emit("new_message", data);
      });
    });

    // 模型正文流式增量（不含推理过程），后端在生成期间持续推送
    this.socket.on("chat_delta", (data) => {
      this.emit("chat_delta", data);
    });

    // 事件列表行级状态变化（分析完成/失败等），后端广播到全局 events 房间
    this.socket.on("event_list_update", (data) => {
      this.emit("event_list_update", data);
    });

    this.socket.connect();
  }

  disconnect() {
    this.socket?.disconnect();
    this.socket = null;
    this.status = "disconnected";
  }

  send(event: string, data: Record<string, any>) {
    if (!this.socket?.connected) return false;
    this.socket.emit(event, data);
    return true;
  }

  join(eventId: number | string) {
    if (!eventId) return;
    const room = String(eventId);
    this.joinedRooms.add(room);
    if (this.socket?.connected) {
      this.socket.emit("join", { event_id: room });
      this.socket.emit("join_event", { event_id: room });
      this.socket.emit("subscribe", { event_id: room });
    }
  }

  leave(eventId: number | string) {
    if (!eventId) return;
    const room = String(eventId);
    this.joinedRooms.delete(room);
    if (this.socket?.connected) {
      this.socket.emit("leave", { event_id: room });
      this.socket.emit("leave_event", { event_id: room });
      this.socket.emit("unsubscribe", { event_id: room });
    }
  }

  on(event: SocketEvent, callback: Listener) {
    if (!this.listeners.has(event)) this.listeners.set(event, []);
    const callbacks = this.listeners.get(event);
    if (callbacks && !callbacks.includes(callback)) callbacks.push(callback);
    if (event === "connected" && this.connected) callback();
  }

  off(event: SocketEvent, callback: Listener) {
    const callbacks = this.listeners.get(event);
    if (!callbacks) return;
    const index = callbacks.indexOf(callback);
    if (index >= 0) callbacks.splice(index, 1);
  }

  private emit(event: SocketEvent, data?: any) {
    this.listeners.get(event)?.forEach((callback) => callback(data));
  }

  private rejoinRooms() {
    this.joinedRooms.forEach((eventId) => {
      this.socket?.emit("join", { event_id: eventId });
      this.socket?.emit("join_event", { event_id: eventId });
      this.socket?.emit("subscribe", { event_id: eventId });
    });
  }
}

export const deepflowSocket = new DeepflowSocketManager();
export default deepflowSocket;
