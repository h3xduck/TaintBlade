/****************************************************************************
** Meta object code from reading C++ file 'PinConfigurationDialog.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../PinTracerUI/PinConfigurationDialog.h"
#include <QtGui/qtextcursor.h>
#include <QtCore/qmetatype.h>

#if __has_include(<QtCore/qtmochelpers.h>)
#include <QtCore/qtmochelpers.h>
#else
QT_BEGIN_MOC_NAMESPACE
#endif


#include <memory>

#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'PinConfigurationDialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {

#ifdef QT_MOC_HAS_STRINGDATA
struct qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS_t {};
static constexpr auto qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS = QtMocHelpers::stringData(
    "PinConfigurationDialog",
    "on_outputDirBrowseButton_clicked",
    "",
    "on_pinExeBrowseButton_clicked",
    "on_tracerdllBrowseButton_clicked",
    "on_buttonBox_rejected",
    "on_buttonBox_accepted"
);
#else  // !QT_MOC_HAS_STRING_DATA
struct qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS_t {
    uint offsetsAndSizes[14];
    char stringdata0[23];
    char stringdata1[33];
    char stringdata2[1];
    char stringdata3[30];
    char stringdata4[33];
    char stringdata5[22];
    char stringdata6[22];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS_t qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS = {
    {
        QT_MOC_LITERAL(0, 22),  // "PinConfigurationDialog"
        QT_MOC_LITERAL(23, 32),  // "on_outputDirBrowseButton_clicked"
        QT_MOC_LITERAL(56, 0),  // ""
        QT_MOC_LITERAL(57, 29),  // "on_pinExeBrowseButton_clicked"
        QT_MOC_LITERAL(87, 32),  // "on_tracerdllBrowseButton_clicked"
        QT_MOC_LITERAL(120, 21),  // "on_buttonBox_rejected"
        QT_MOC_LITERAL(142, 21)   // "on_buttonBox_accepted"
    },
    "PinConfigurationDialog",
    "on_outputDirBrowseButton_clicked",
    "",
    "on_pinExeBrowseButton_clicked",
    "on_tracerdllBrowseButton_clicked",
    "on_buttonBox_rejected",
    "on_buttonBox_accepted"
};
#undef QT_MOC_LITERAL
#endif // !QT_MOC_HAS_STRING_DATA
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_CLASSPinConfigurationDialogENDCLASS[] = {

 // content:
      11,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       1,    0,   44,    2, 0x08,    1 /* Private */,
       3,    0,   45,    2, 0x08,    2 /* Private */,
       4,    0,   46,    2, 0x08,    3 /* Private */,
       5,    0,   47,    2, 0x08,    4 /* Private */,
       6,    0,   48,    2, 0x08,    5 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject PinConfigurationDialog::staticMetaObject = { {
    QMetaObject::SuperData::link<QDialog::staticMetaObject>(),
    qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS.offsetsAndSizes,
    qt_meta_data_CLASSPinConfigurationDialogENDCLASS,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<PinConfigurationDialog, std::true_type>,
        // method 'on_outputDirBrowseButton_clicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'on_pinExeBrowseButton_clicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'on_tracerdllBrowseButton_clicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'on_buttonBox_rejected'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'on_buttonBox_accepted'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void PinConfigurationDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<PinConfigurationDialog *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->on_outputDirBrowseButton_clicked(); break;
        case 1: _t->on_pinExeBrowseButton_clicked(); break;
        case 2: _t->on_tracerdllBrowseButton_clicked(); break;
        case 3: _t->on_buttonBox_rejected(); break;
        case 4: _t->on_buttonBox_accepted(); break;
        default: ;
        }
    }
    (void)_a;
}

const QMetaObject *PinConfigurationDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *PinConfigurationDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CLASSPinConfigurationDialogENDCLASS.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int PinConfigurationDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 5)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 5;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 5)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 5;
    }
    return _id;
}
QT_WARNING_POP
