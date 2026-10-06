using PkiPortal.Models;

namespace PkiPortal.Services;

public interface IHeldRequestStore
{
    /// <summary>
    /// Salva una richiesta trattenuta dal portale.
    /// </summary>
    Task<HeldCertificateRequest> HoldRequestAsync(HeldCertificateRequest request);

    /// <summary>
    /// Recupera una richiesta trattenuta per il suo HoldId.
    /// </summary>
    Task<HeldCertificateRequest?> GetByHoldIdAsync(string holdId);

    /// <summary>
    /// Recupera una richiesta trattenuta in base al CaRequestId e CaId opzionale.
    /// </summary>
    Task<HeldCertificateRequest?> GetByCaRequestIdAsync(string? caId, int caRequestId);

    /// <summary>
    /// Recupera tutte le richieste in stato PendingApproval.
    /// </summary>
    Task<List<HeldCertificateRequest>> GetPendingRequestsAsync();

    /// <summary>
    /// Recupera tutte le richieste (qualsiasi stato), con filtro opzionale.
    /// </summary>
    Task<List<HeldCertificateRequest>> GetAllRequestsAsync(HoldStatus? statusFilter = null);

    /// <summary>
    /// Approva una richiesta: cambia lo stato a Approved e restituisce i dati del certificato.
    /// </summary>
    Task<HeldCertificateRequest?> ApproveRequestAsync(string holdId, string approvedBy);

    /// <summary>
    /// Rifiuta una richiesta: cambia lo stato a Rejected.
    /// </summary>
    Task<HeldCertificateRequest?> RejectRequestAsync(string holdId, string rejectedBy, string? reason);

    /// <summary>
    /// Salva o aggiorna una generica richiesta certificato (emessa, pending o trattenuta).
    /// </summary>
    Task<HeldCertificateRequest> SaveRequestAsync(HeldCertificateRequest request);

    /// <summary>
    /// Aggiorna una richiesta esistente (es. certificato recuperato e stato aggiornato).
    /// </summary>
    Task<HeldCertificateRequest?> UpdateRequestAsync(HeldCertificateRequest request);

    /// <summary>
    /// Recupera tutte le richieste inoltrate da uno specifico utente (per storico e download personale).
    /// </summary>
    Task<List<HeldCertificateRequest>> GetRequestsByUserAsync(string userName);
}
