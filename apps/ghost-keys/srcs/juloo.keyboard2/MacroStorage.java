package juloo.keyboard2;

import android.content.Context;
import android.content.SharedPreferences;
import org.json.JSONArray;
import org.json.JSONObject;
import java.util.ArrayList;
import java.util.List;

/**
 * Handles storage and retrieval of user-defined macros.
 * Macros are stored in SharedPreferences as JSON.
 */
public class MacroStorage
{
  private static final String PREFS_NAME = "ghost_keys_macros";
  private static final String KEY_MACROS = "saved_macros";

  private SharedPreferences _prefs;
  private List<Macro> _macros;

  public static class Macro
  {
    public String label;
    public String command;
    public long timestamp;

    public Macro(String label, String command)
    {
      this.label = label;
      this.command = command;
      this.timestamp = System.currentTimeMillis();
    }

    public Macro(String label, String command, long timestamp)
    {
      this.label = label;
      this.command = command;
      this.timestamp = timestamp;
    }
  }

  public MacroStorage(Context context)
  {
    _prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    _macros = new ArrayList<>();
    load();
  }

  /** Load macros from storage */
  private void load()
  {
    _macros.clear();
    String json = _prefs.getString(KEY_MACROS, "[]");
    try
    {
      JSONArray arr = new JSONArray(json);
      for (int i = 0; i < arr.length(); i++)
      {
        JSONObject obj = arr.getJSONObject(i);
        _macros.add(new Macro(
          obj.getString("label"),
          obj.getString("command"),
          obj.optLong("timestamp", System.currentTimeMillis())
        ));
      }
    }
    catch (Exception e)
    {
      // If parsing fails, start with empty list
      _macros.clear();
    }
  }

  /** Save macros to storage */
  private void save()
  {
    try
    {
      JSONArray arr = new JSONArray();
      for (Macro m : _macros)
      {
        JSONObject obj = new JSONObject();
        obj.put("label", m.label);
        obj.put("command", m.command);
        obj.put("timestamp", m.timestamp);
        arr.put(obj);
      }
      _prefs.edit().putString(KEY_MACROS, arr.toString()).apply();
    }
    catch (Exception e)
    {
      // Ignore save errors
    }
  }

  /** Get all macros */
  public List<Macro> getMacros()
  {
    return new ArrayList<>(_macros);
  }

  /** Add a new macro */
  public void addMacro(String label, String command)
  {
    _macros.add(new Macro(label, command));
    save();
  }

  /** Delete a macro by index */
  public void deleteMacro(int index)
  {
    if (index >= 0 && index < _macros.size())
    {
      _macros.remove(index);
      save();
    }
  }

  /** Delete a macro by label */
  public void deleteMacro(String label)
  {
    for (int i = 0; i < _macros.size(); i++)
    {
      if (_macros.get(i).label.equals(label))
      {
        _macros.remove(i);
        save();
        return;
      }
    }
  }

  /** Move a macro to a new position */
  public void moveMacro(int fromIndex, int toIndex)
  {
    if (fromIndex >= 0 && fromIndex < _macros.size() &&
        toIndex >= 0 && toIndex < _macros.size())
    {
      Macro m = _macros.remove(fromIndex);
      _macros.add(toIndex, m);
      save();
    }
  }

  /** Update a macro's label or command */
  public void updateMacro(int index, String label, String command)
  {
    if (index >= 0 && index < _macros.size())
    {
      Macro m = _macros.get(index);
      m.label = label;
      m.command = command;
      save();
    }
  }

  /** Get macro count */
  public int getCount()
  {
    return _macros.size();
  }

  /** Check if a label already exists */
  public boolean labelExists(String label)
  {
    for (Macro m : _macros)
    {
      if (m.label.equals(label))
        return true;
    }
    return false;
  }
}
